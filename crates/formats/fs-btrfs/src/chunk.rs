//! Logical-to-physical chunk mappings, including mirrored and striped layouts.

mod validation;

use alloc::vec::Vec;

use crate::bytes::slice;
#[cfg(any(test, feature = "fuzzing"))]
use crate::key::DiskKey;
use crate::key::{DISK_KEY_SIZE, RawDiskKey};
use crate::{BtrfsError, Result};
use validation::valid_profile_geometry;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned,
};

pub(crate) const CHUNK_ITEM_KEY: u8 = 228;
const FIRST_CHUNK_TREE_OBJECT_ID: u64 = 256;
const CHUNK_HEADER_SIZE: usize = 48;
const STRIPE_SIZE: usize = 32;
const BTRFS_STRIPE_LENGTH: u64 = 64 * 1024;
const MAX_CHUNK_LENGTH: u64 = 0xffff_ffff_u64 * BTRFS_STRIPE_LENGTH;
#[cfg(any(test, feature = "fuzzing"))]
const CANONICAL_SYSTEM_CHUNK_LENGTH: u64 = 64 * 1024 * 1024;
#[cfg(any(test, feature = "fuzzing"))]
const EXTENT_TREE_OBJECT_ID: u64 = 2;

const TYPE_DATA: u64 = 1_u64 << 0;
const TYPE_SYSTEM: u64 = 1_u64 << 1;
const TYPE_METADATA: u64 = 1_u64 << 2;
const FLAG_REMAPPED: u64 = 1_u64 << 11;
const TYPE_METADATA_REMAP: u64 = 1_u64 << 12;
const TYPE_MASK: u64 = TYPE_DATA | TYPE_SYSTEM | TYPE_METADATA | TYPE_METADATA_REMAP;
const MIXED_GROUPS_INCOMPAT: u64 = 1_u64 << 2;

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
const VALID_FLAGS: u64 = TYPE_MASK | PROFILE_MASK | FLAG_REMAPPED;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawChunkHeader {
    length: U64<LE>,
    _owner: U64<LE>,
    stripe_length: U64<LE>,
    flags: U64<LE>,
    _io_align: U32<LE>,
    _io_width: U32<LE>,
    sector_size: U32<LE>,
    stripe_count: U16<LE>,
    sub_stripes: U16<LE>,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawChunkStripe {
    device_id: U64<LE>,
    offset: U64<LE>,
    device_uuid: [u8; 16],
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawSystemChunkItemHeader {
    key: RawDiskKey,
    chunk: RawChunkHeader,
}

const _: [(); CHUNK_HEADER_SIZE] = [(); core::mem::size_of::<RawChunkHeader>()];
const _: [(); STRIPE_SIZE] = [(); core::mem::size_of::<RawChunkStripe>()];
const SYSTEM_CHUNK_ITEM_HEADER_SIZE: usize = core::mem::size_of::<RawSystemChunkItemHeader>();
const _: [(); 65] = [(); SYSTEM_CHUNK_ITEM_HEADER_SIZE];
pub(crate) const MIN_SYSTEM_CHUNK_ARRAY_SIZE: usize = SYSTEM_CHUNK_ITEM_HEADER_SIZE + STRIPE_SIZE;

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn canonical_system_chunk(
    logical: u64,
    sector_size: u32,
    device_id: u64,
    device_uuid: [u8; 16],
) -> [u8; MIN_SYSTEM_CHUNK_ARRAY_SIZE] {
    let header = RawSystemChunkItemHeader {
        key: DiskKey {
            object_id: FIRST_CHUNK_TREE_OBJECT_ID,
            item_type: CHUNK_ITEM_KEY,
            offset: logical,
        }
        .into(),
        chunk: RawChunkHeader {
            length: U64::new(CANONICAL_SYSTEM_CHUNK_LENGTH),
            _owner: U64::new(EXTENT_TREE_OBJECT_ID),
            stripe_length: U64::new(BTRFS_STRIPE_LENGTH),
            flags: U64::new(TYPE_SYSTEM),
            _io_align: U32::new(
                u32::try_from(BTRFS_STRIPE_LENGTH).expect("stripe length fits u32"),
            ),
            _io_width: U32::new(
                u32::try_from(BTRFS_STRIPE_LENGTH).expect("stripe length fits u32"),
            ),
            sector_size: U32::new(sector_size),
            stripe_count: U16::new(1),
            sub_stripes: U16::new(0),
        },
    };
    let stripe = RawChunkStripe {
        device_id: U64::new(device_id),
        offset: U64::new(logical),
        device_uuid,
    };
    let mut data = [0_u8; MIN_SYSTEM_CHUNK_ARRAY_SIZE];
    data[..SYSTEM_CHUNK_ITEM_HEADER_SIZE].copy_from_slice(header.as_bytes());
    data[SYSTEM_CHUNK_ITEM_HEADER_SIZE..].copy_from_slice(stripe.as_bytes());
    data
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkProfile {
    Single,
    Raid0,
    Raid1,
    Dup,
    Raid10,
    Raid5,
    Raid6,
    Raid1C3,
    Raid1C4,
}

impl ChunkProfile {
    const fn from_flags(flags: u64) -> Option<Self> {
        match flags & PROFILE_MASK {
            0 => Some(Self::Single),
            PROFILE_RAID0 => Some(Self::Raid0),
            PROFILE_RAID1 => Some(Self::Raid1),
            PROFILE_DUP => Some(Self::Dup),
            PROFILE_RAID10 => Some(Self::Raid10),
            PROFILE_RAID5 => Some(Self::Raid5),
            PROFILE_RAID6 => Some(Self::Raid6),
            PROFILE_RAID1C3 => Some(Self::Raid1C3),
            PROFILE_RAID1C4 => Some(Self::Raid1C4),
            _ => None,
        }
    }
}

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
    pub(crate) device_uuid: [u8; 16],
    pub(crate) offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MappedSegment {
    pub(crate) locations: Vec<PhysicalLocation>,
    pub(crate) length: usize,
    pub(crate) raid56: Option<Raid56Segment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Raid56Segment {
    pub(crate) stripes: Vec<PhysicalLocation>,
    pub(crate) data_stripes: usize,
    pub(crate) parity_stripes: usize,
    pub(crate) target_data: usize,
}

impl Raid56Segment {
    pub(crate) fn replica_count(&self) -> usize {
        if self.parity_stripes == 1 {
            2
        } else {
            self.stripes.len()
        }
    }

    pub(crate) fn forced_missing(&self, replica: usize) -> Option<usize> {
        let candidate = replica.checked_sub(2)?;
        (0..self.data_stripes)
            .filter(|index| *index != self.target_data)
            .chain(core::iter::once(self.data_stripes))
            .nth(candidate)
    }
}

impl ChunkMapping {
    pub(crate) fn parse(
        logical: u64,
        data: &[u8],
        sector_size: u32,
        incompat_flags: u64,
    ) -> Result<Self> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(BtrfsError::InvalidChunk { logical });
        }
        let raw = RawChunkHeader::ref_from_bytes(&data[..CHUNK_HEADER_SIZE])
            .map_err(|_| BtrfsError::InvalidChunk { logical })?;
        let stripe_count = usize::from(raw.stripe_count.get());
        let stripe_bytes = stripe_count
            .checked_mul(STRIPE_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let expected = CHUNK_HEADER_SIZE
            .checked_add(stripe_bytes)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if data.len() != expected || (stripe_count == 0 && raw.flags.get() & FLAG_REMAPPED == 0) {
            return Err(BtrfsError::InvalidChunk { logical });
        }

        let mut stripes = Vec::with_capacity(stripe_count);
        let serialized_stripes = data
            .get(CHUNK_HEADER_SIZE..expected)
            .ok_or(BtrfsError::InvalidChunk { logical })?;
        for bytes in serialized_stripes.chunks_exact(STRIPE_SIZE) {
            let raw_stripe = RawChunkStripe::ref_from_bytes(bytes)
                .map_err(|_| BtrfsError::InvalidChunk { logical })?;
            stripes.push(ChunkStripe {
                device_id: raw_stripe.device_id.get(),
                offset: raw_stripe.offset.get(),
                device_uuid: raw_stripe.device_uuid,
            });
        }

        let mapping = Self {
            logical,
            length: raw.length.get(),
            stripe_length: raw.stripe_length.get(),
            flags: raw.flags.get(),
            sub_stripes: raw.sub_stripes.get(),
            stripes,
        };
        mapping.validate(sector_size, incompat_flags, raw.sector_size.get())?;
        Ok(mapping)
    }

    fn validate(
        &self,
        sector_size: u32,
        incompat_flags: u64,
        chunk_sector_size: u32,
    ) -> Result<()> {
        let profile = ChunkProfile::from_flags(self.flags);
        let chunk_type = self.flags & TYPE_MASK;
        let stripe_count = self.stripes.len();
        let remapped = self.is_remapped();
        let remap_tree = incompat_flags & crate::superblock::REMAP_TREE_INCOMPAT != 0;
        let chunk_matches_sector_size = chunk_sector_size == sector_size;
        let sector_size = u64::from(sector_size);
        let valid_type = matches!(chunk_type, TYPE_DATA | TYPE_SYSTEM | TYPE_METADATA)
            || (chunk_type == TYPE_METADATA_REMAP && remap_tree)
            || (chunk_type == TYPE_DATA | TYPE_METADATA
                && incompat_flags & MIXED_GROUPS_INCOMPAT != 0);
        let valid_stripes = if remapped {
            remap_tree
                && if stripe_count == 0 {
                    self.sub_stripes == 0
                } else {
                    valid_profile_geometry(profile, stripe_count, self.sub_stripes, false)
                }
        } else {
            valid_profile_geometry(profile, stripe_count, self.sub_stripes, true)
        };
        let valid = sector_size != 0
            && self.flags & !VALID_FLAGS == 0
            && profile.is_some()
            && valid_type
            && chunk_matches_sector_size
            && self.logical.is_multiple_of(sector_size)
            && self.length.is_multiple_of(sector_size)
            && self.length != 0
            && self.length < MAX_CHUNK_LENGTH
            && self.stripe_length == BTRFS_STRIPE_LENGTH
            && valid_stripes;
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

    pub(crate) fn is_readable_with(
        &self,
        mut device_available: impl FnMut(&ChunkStripe) -> bool,
    ) -> bool {
        if self.is_remapped() && self.stripes.is_empty() {
            return true;
        }
        let profile = ChunkProfile::from_flags(self.flags);
        match profile {
            Some(ChunkProfile::Single | ChunkProfile::Raid0) => {
                self.stripes.iter().all(&mut device_available)
            }
            Some(
                ChunkProfile::Dup
                | ChunkProfile::Raid1
                | ChunkProfile::Raid1C3
                | ChunkProfile::Raid1C4,
            ) => self.stripes.iter().any(&mut device_available),
            Some(ChunkProfile::Raid10) => {
                let copies = usize::from(self.sub_stripes);
                self.stripes
                    .chunks_exact(copies)
                    .all(|replicas| replicas.iter().any(&mut device_available))
            }
            Some(ChunkProfile::Raid5 | ChunkProfile::Raid6) => {
                let parity_stripes = usize::from(matches!(profile, Some(ChunkProfile::Raid5)))
                    + 2 * usize::from(matches!(profile, Some(ChunkProfile::Raid6)));
                self.stripes
                    .iter()
                    .filter(|stripe| !device_available(stripe))
                    .count()
                    <= parity_stripes
            }
            None => false,
        }
    }

    pub(crate) fn contains(&self, logical: u64) -> bool {
        logical >= self.logical && logical < self.logical.saturating_add(self.length)
    }

    pub(crate) const fn is_remapped(&self) -> bool {
        self.flags & FLAG_REMAPPED != 0
    }

    pub(crate) fn uses_raid_stripe_tree(&self) -> bool {
        self.flags & TYPE_MASK == TYPE_DATA
            && matches!(
                ChunkProfile::from_flags(self.flags),
                Some(
                    ChunkProfile::Raid0
                        | ChunkProfile::Raid1
                        | ChunkProfile::Dup
                        | ChunkProfile::Raid10
                        | ChunkProfile::Raid1C3
                        | ChunkProfile::Raid1C4
                )
            )
    }

    pub(crate) fn raid_stripe_count(&self) -> Option<usize> {
        match ChunkProfile::from_flags(self.flags)? {
            ChunkProfile::Raid0 => Some(1),
            ChunkProfile::Raid1 | ChunkProfile::Dup | ChunkProfile::Raid10 => Some(2),
            ChunkProfile::Raid1C3 => Some(3),
            ChunkProfile::Raid1C4 => Some(4),
            ChunkProfile::Single | ChunkProfile::Raid5 | ChunkProfile::Raid6 => None,
        }
    }

    pub(crate) fn device_uuid(&self, device_id: u64) -> Option<[u8; 16]> {
        self.stripes
            .iter()
            .find(|stripe| stripe.device_id == device_id)
            .map(|stripe| stripe.device_uuid)
    }

    pub(crate) fn map(&self, logical: u64, requested: usize) -> Result<MappedSegment> {
        if !self.contains(logical) {
            return Err(BtrfsError::LogicalAddressUnmapped { logical });
        }
        let relative = logical - self.logical;
        let chunk_remaining = self.length - relative;
        let requested_u64 = u64::try_from(requested).map_err(|_| BtrfsError::IntegerOverflow)?;
        let maximum = chunk_remaining.min(requested_u64);
        let profile =
            ChunkProfile::from_flags(self.flags).ok_or(BtrfsError::UnsupportedChunkProfile {
                profile: self.flags & PROFILE_MASK,
            })?;

        match profile {
            ChunkProfile::Single
            | ChunkProfile::Dup
            | ChunkProfile::Raid1
            | ChunkProfile::Raid1C3
            | ChunkProfile::Raid1C4 => self.map_mirrored(relative, maximum),
            ChunkProfile::Raid0 => self.map_raid0(relative, maximum),
            ChunkProfile::Raid10 => self.map_raid10(relative, maximum),
            ChunkProfile::Raid5 => self.map_raid56(relative, maximum, 1),
            ChunkProfile::Raid6 => self.map_raid56(relative, maximum, 2),
        }
    }

    fn map_mirrored(&self, relative: u64, maximum: u64) -> Result<MappedSegment> {
        let mut locations = Vec::with_capacity(self.stripes.len());
        for stripe in &self.stripes {
            locations.push(PhysicalLocation {
                device_id: stripe.device_id,
                device_uuid: stripe.device_uuid,
                offset: stripe
                    .offset
                    .checked_add(relative)
                    .ok_or(BtrfsError::IntegerOverflow)?,
            });
        }
        Ok(MappedSegment {
            locations,
            length: usize::try_from(maximum).map_err(|_| BtrfsError::IntegerOverflow)?,
            raid56: None,
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
                device_uuid: stripe.device_uuid,
                offset: physical,
            }],
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
            raid56: None,
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
                device_uuid: stripe.device_uuid,
                offset: physical,
            });
        }
        Ok(MappedSegment {
            locations,
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
            raid56: None,
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
        let stripe_set_offset = full_stripe
            .checked_mul(self.stripe_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let physical = stripe
            .offset
            .checked_add(stripe_set_offset)
            .and_then(|offset| offset.checked_add(within_stripe))
            .ok_or(BtrfsError::IntegerOverflow)?;
        let mut recovery_stripes = Vec::with_capacity(self.stripes.len());
        for logical_index in 0..self.stripes.len() {
            let logical_index =
                u64::try_from(logical_index).map_err(|_| BtrfsError::IntegerOverflow)?;
            let physical_index = usize::try_from(
                full_stripe
                    .checked_add(logical_index)
                    .ok_or(BtrfsError::IntegerOverflow)?
                    % stripe_count,
            )
            .map_err(|_| BtrfsError::IntegerOverflow)?;
            let recovery_stripe = &self.stripes[physical_index];
            recovery_stripes.push(PhysicalLocation {
                device_id: recovery_stripe.device_id,
                device_uuid: recovery_stripe.device_uuid,
                offset: recovery_stripe
                    .offset
                    .checked_add(stripe_set_offset)
                    .and_then(|offset| offset.checked_add(within_stripe))
                    .ok_or(BtrfsError::IntegerOverflow)?,
            });
        }
        Ok(MappedSegment {
            locations: alloc::vec![PhysicalLocation {
                device_id: stripe.device_id,
                device_uuid: stripe.device_uuid,
                offset: physical,
            }],
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
            raid56: Some(Raid56Segment {
                stripes: recovery_stripes,
                data_stripes,
                parity_stripes,
                target_data: usize::try_from(data_index)
                    .map_err(|_| BtrfsError::IntegerOverflow)?,
            }),
        })
    }
}

pub(crate) fn parse_system_chunks(
    data: &[u8],
    sector_size: u32,
    incompat_flags: u64,
) -> Result<Vec<ChunkMapping>> {
    if !(MIN_SYSTEM_CHUNK_ARRAY_SIZE..=crate::superblock::SYSTEM_CHUNK_ARRAY_CAPACITY)
        .contains(&data.len())
    {
        return Err(BtrfsError::InvalidSystemChunkArraySize {
            actual: u32::try_from(data.len()).unwrap_or(u32::MAX),
        });
    }
    let mut chunks = Vec::new();
    let mut position = 0_usize;
    while position < data.len() {
        let raw = RawSystemChunkItemHeader::ref_from_bytes(slice(
            data,
            position,
            SYSTEM_CHUNK_ITEM_HEADER_SIZE,
        )?)
        .map_err(|_| BtrfsError::InvalidChunk { logical: 0 })?;
        let key = raw.key.to_disk_key();
        if key.object_id != FIRST_CHUNK_TREE_OBJECT_ID || key.item_type != CHUNK_ITEM_KEY {
            return Err(BtrfsError::MalformedItem {
                object_id: key.object_id,
                item_type: key.item_type,
                offset: key.offset,
            });
        }
        if raw.chunk.flags.get() & TYPE_SYSTEM == 0 {
            return Err(BtrfsError::InvalidChunk {
                logical: key.offset,
            });
        }
        let stripe_bytes = usize::from(raw.chunk.stripe_count.get())
            .checked_mul(STRIPE_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let size = CHUNK_HEADER_SIZE
            .checked_add(stripe_bytes)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let chunk_start = position
            .checked_add(DISK_KEY_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let chunk_data = slice(data, chunk_start, size)?;
        chunks.push(ChunkMapping::parse(
            key.offset,
            chunk_data,
            sector_size,
            incompat_flags,
        )?);
        position = chunk_start
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
            flags: flags | TYPE_DATA,
            sub_stripes,
            stripes,
        }
    }

    fn validate(mapping: &ChunkMapping) -> Result<()> {
        mapping.validate(4096, 0, 4096)
    }

    #[test]
    fn single_mapping_preserves_relative_offset() {
        let chunk = mapping(0, 0, alloc::vec![stripe(7, 0x20_0000)]);
        validate(&chunk).expect("single chunk");
        let mapped = chunk.map(0x12_3456, 4096).expect("map");

        assert_eq!(mapped.length, 4096);
        assert_eq!(
            mapped.locations,
            alloc::vec![PhysicalLocation {
                device_id: 7,
                device_uuid: [0; 16],
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
        validate(&chunk).expect("raid1 chunk");
        let mapped = chunk.map(0x11_0000, 512).expect("map");

        assert_eq!(
            mapped.locations,
            alloc::vec![
                PhysicalLocation {
                    device_id: 1,
                    device_uuid: [0; 16],
                    offset: 0x21_0000
                },
                PhysicalLocation {
                    device_id: 2,
                    device_uuid: [0; 16],
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
        validate(&chunk).expect("raid0 chunk");

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
        validate(&chunk).expect("one-stripe raid0");

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
        validate(&chunk).expect("raid10 chunk");

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
        validate(&chunk).expect("structurally valid raid5");

        let first = chunk.map(0x10_0000, 4096).expect("first data stripe");
        assert_eq!(first.locations[0].device_id, 1);
        assert_eq!(first.locations[0].offset, 0x20_0000);
        let first_recovery = first.raid56.expect("RAID5 recovery geometry");
        assert_eq!(first_recovery.target_data, 0);
        assert_eq!(
            first_recovery
                .stripes
                .iter()
                .map(|location| location.device_id)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );

        let second = chunk.map(0x11_0000, 4096).expect("second data stripe");
        assert_eq!(second.locations[0].device_id, 2);
        assert_eq!(second.locations[0].offset, 0x30_0000);

        let rotated = chunk.map(0x12_0000, 4096).expect("rotated parity");
        assert_eq!(rotated.locations[0].device_id, 2);
        assert_eq!(rotated.locations[0].offset, 0x31_0000);
        let rotated_recovery = rotated.raid56.expect("rotated RAID5 geometry");
        assert_eq!(
            rotated_recovery
                .stripes
                .iter()
                .map(|location| location.device_id)
                .collect::<Vec<_>>(),
            [2, 3, 1]
        );
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
        validate(&chunk).expect("structurally valid raid6");

        let rotated = chunk.map(0x12_0000, 4096).expect("second full stripe");
        assert_eq!(rotated.locations[0].device_id, 2);
        assert_eq!(rotated.locations[0].offset, 0x31_0000);
        let recovery = rotated.raid56.expect("RAID6 recovery geometry");
        assert_eq!(recovery.replica_count(), 4);
        assert_eq!(recovery.forced_missing(0), None);
        assert_eq!(recovery.forced_missing(1), None);
        assert_eq!(recovery.forced_missing(2), Some(1));
        assert_eq!(recovery.forced_missing(3), Some(2));
        assert_eq!(
            recovery
                .stripes
                .iter()
                .map(|location| location.device_id)
                .collect::<Vec<_>>(),
            [2, 3, 4, 1]
        );
    }

    #[test]
    fn profile_redundancy_controls_degraded_readability() {
        let nonredundant = mapping(PROFILE_RAID0, 0, alloc::vec![stripe(1, 0), stripe(2, 0)]);
        assert!(!nonredundant.is_readable_with(|stripe| stripe.device_id == 1));

        let mirrored = mapping(PROFILE_RAID1, 0, alloc::vec![stripe(1, 0), stripe(2, 0)]);
        assert!(mirrored.is_readable_with(|stripe| stripe.device_id == 1));

        let paired_mirrors = mapping(
            PROFILE_RAID10,
            2,
            alloc::vec![stripe(1, 0), stripe(2, 0), stripe(3, 0), stripe(4, 0)],
        );
        assert!(paired_mirrors.is_readable_with(|stripe| matches!(stripe.device_id, 1 | 3)));
        assert!(!paired_mirrors.is_readable_with(|stripe| matches!(stripe.device_id, 1 | 2)));

        let single_parity = mapping(
            PROFILE_RAID5,
            0,
            alloc::vec![stripe(1, 0), stripe(2, 0), stripe(3, 0)],
        );
        assert!(single_parity.is_readable_with(|stripe| stripe.device_id != 2));
        assert!(!single_parity.is_readable_with(|stripe| stripe.device_id == 1));

        let double_parity = mapping(
            PROFILE_RAID6,
            0,
            alloc::vec![stripe(1, 0), stripe(2, 0), stripe(3, 0), stripe(4, 0),],
        );
        assert!(double_parity.is_readable_with(|stripe| matches!(stripe.device_id, 1 | 4)));
        assert!(!double_parity.is_readable_with(|stripe| stripe.device_id == 1));
    }

    #[test]
    fn fixed_replica_profiles_require_their_exact_stripe_counts() {
        for (profile, expected) in [
            (PROFILE_DUP, 2_usize),
            (PROFILE_RAID1, 2),
            (PROFILE_RAID1C3, 3),
            (PROFILE_RAID1C4, 4),
        ] {
            let valid = mapping(
                profile,
                0,
                (0..expected)
                    .map(|index| stripe(u64::try_from(index + 1).expect("device ID"), 0x20_0000))
                    .collect(),
            );
            validate(&valid).expect("exact replica count");

            let mut extra = valid;
            extra.stripes.push(stripe(99, 0x30_0000));
            assert!(matches!(
                validate(&extra),
                Err(BtrfsError::InvalidChunk { .. })
            ));
        }
    }

    #[test]
    fn raid10_requires_pairs_of_sub_stripes() {
        let mut chunk = mapping(
            PROFILE_RAID10,
            3,
            alloc::vec![
                stripe(1, 0x20_0000),
                stripe(2, 0x30_0000),
                stripe(3, 0x40_0000),
            ],
        );
        assert!(validate(&chunk).is_err());

        chunk.sub_stripes = 2;
        assert!(validate(&chunk).is_err());
        chunk.stripes.push(stripe(4, 0x50_0000));
        validate(&chunk).expect("paired RAID10 stripes");
    }

    #[test]
    fn chunk_geometry_and_type_flags_match_the_superblock() {
        let mut chunk = mapping(0, 0, alloc::vec![stripe(1, 0x20_0000)]);

        chunk.flags = 0;
        assert!(validate(&chunk).is_err());

        chunk.flags = TYPE_SYSTEM | TYPE_DATA;
        assert!(validate(&chunk).is_err());

        chunk.flags = TYPE_DATA | TYPE_METADATA;
        assert!(validate(&chunk).is_err());
        chunk
            .validate(4096, MIXED_GROUPS_INCOMPAT, 4096)
            .expect("mixed block group feature");

        chunk.logical += 1;
        assert!(chunk.validate(4096, MIXED_GROUPS_INCOMPAT, 4096).is_err());
        chunk.logical -= 1;
        assert!(chunk.validate(4096, MIXED_GROUPS_INCOMPAT, 8192).is_err());
    }

    #[test]
    fn system_chunk_array_requires_on_disk_superblock_bounds() {
        assert!(matches!(
            parse_system_chunks(&[], 4096, 0),
            Err(BtrfsError::InvalidSystemChunkArraySize { actual: 0 })
        ));
        let oversized = alloc::vec![0_u8; crate::superblock::SYSTEM_CHUNK_ARRAY_CAPACITY + 1];
        assert!(matches!(
            parse_system_chunks(&oversized, 4096, 0),
            Err(BtrfsError::InvalidSystemChunkArraySize { .. })
        ));
    }
}
