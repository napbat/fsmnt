use alloc::vec::Vec;

use crate::{BtrfsError, Result};

use super::{SUPERBLOCK_MIRROR_OFFSETS, SUPERBLOCK_SIZE};

/// First-zone offsets for Btrfs's three zoned superblock log pairs.
pub const ZONED_SUPERBLOCK_LOG_OFFSETS: [u64; 3] =
    [0, 512 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024 * 1024];

/// Smallest zoned-device zone size supported by Btrfs.
pub const MIN_ZONE_SIZE: u64 = 4 * 1024 * 1024;

/// Largest zoned-device zone size supported by Btrfs.
pub const MAX_ZONE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Write-ordering model of one zone used by a Btrfs superblock log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtrfsZoneType {
    /// Random writes are permitted and there is no meaningful write pointer.
    Conventional,
    /// Writes must be issued sequentially at the current write pointer.
    SequentialWriteRequired,
    /// Sequential writes are preferred, but random writes remain permitted.
    SequentialWritePreferred,
}

impl BtrfsZoneType {
    const fn is_conventional(self) -> bool {
        matches!(self, Self::Conventional)
    }
}

/// Current state of one zone used by a Btrfs superblock log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtrfsZoneCondition {
    /// Conventional zone without a write pointer.
    NotWritePointer,
    /// Sequential zone containing no written sectors.
    Empty,
    /// Sequential zone opened implicitly by a write.
    ImplicitOpen,
    /// Sequential zone opened explicitly.
    ExplicitOpen,
    /// Sequential zone closed after one or more writes.
    Closed,
    /// Cached report state representing any active sequential zone.
    Active,
    /// Zone can be read but no longer written.
    ReadOnly,
    /// Zone has no remaining writable capacity.
    Full,
    /// Zone is unavailable for reads and writes.
    Offline,
}

/// Geometry and write state of one reported device zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsZone {
    start: u64,
    length: u64,
    capacity: u64,
    write_pointer: u64,
    zone_type: BtrfsZoneType,
    condition: BtrfsZoneCondition,
}

impl BtrfsZone {
    /// Describe one zone using byte offsets relative to the Btrfs device.
    #[must_use]
    pub const fn new(
        start: u64,
        length: u64,
        capacity: u64,
        write_pointer: u64,
        zone_type: BtrfsZoneType,
        condition: BtrfsZoneCondition,
    ) -> Self {
        Self {
            start,
            length,
            capacity,
            write_pointer,
            zone_type,
            condition,
        }
    }

    /// Byte offset at which this zone begins.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Total zone length in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Writable capacity in bytes.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Current write pointer as a byte offset relative to the device.
    #[must_use]
    pub const fn write_pointer(&self) -> u64 {
        self.write_pointer
    }

    /// Write-ordering model for the zone.
    #[must_use]
    pub const fn zone_type(&self) -> BtrfsZoneType {
        self.zone_type
    }

    /// Current zone condition.
    #[must_use]
    pub const fn condition(&self) -> BtrfsZoneCondition {
        self.condition
    }
}

/// Sparse zone geometry needed to locate Btrfs superblock logs.
///
/// Callers need only provide the two zones at each
/// [`ZONED_SUPERBLOCK_LOG_OFFSETS`] entry that exists on the device. The
/// complete device zone map is deliberately unnecessary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsZonedDevice {
    zone_size: u64,
    zones: Vec<BtrfsZone>,
}

impl BtrfsZonedDevice {
    /// Validate sparse zone geometry for one Btrfs member.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::InvalidZoneSize`] or
    /// [`BtrfsError::InvalidZoneGeometry`] when the report violates Btrfs or
    /// block-zone invariants.
    pub fn new(zone_size: u64, mut zones: Vec<BtrfsZone>) -> Result<Self> {
        if !zone_size.is_power_of_two() || !(MIN_ZONE_SIZE..=MAX_ZONE_SIZE).contains(&zone_size) {
            return Err(BtrfsError::InvalidZoneSize { actual: zone_size });
        }
        zones.sort_unstable_by_key(BtrfsZone::start);
        let mut previous_end = None;
        for zone in &zones {
            validate_zone(*zone, zone_size)?;
            if previous_end.is_some_and(|end| zone.start < end) {
                return Err(BtrfsError::InvalidZoneGeometry { start: zone.start });
            }
            previous_end = Some(
                zone.start
                    .checked_add(zone.length)
                    .ok_or(BtrfsError::IntegerOverflow)?,
            );
        }
        Ok(Self { zone_size, zones })
    }

    /// Uniform zone size in bytes.
    #[must_use]
    pub const fn zone_size(&self) -> u64 {
        self.zone_size
    }

    /// Sparse zones supplied for superblock discovery.
    #[must_use]
    pub fn zones(&self) -> &[BtrfsZone] {
        &self.zones
    }

    pub(super) fn superblock_locations(&self) -> Result<Vec<SuperblockLocation>> {
        let mut locations = Vec::new();
        for (mirror, log_start) in ZONED_SUPERBLOCK_LOG_OFFSETS.into_iter().enumerate() {
            let Some(first) = self.zone_at(log_start) else {
                continue;
            };
            let second_start = log_start
                .checked_add(self.zone_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let Some(second) = self.zone_at(second_start) else {
                return Err(BtrfsError::InvalidZoneGeometry { start: log_start });
            };
            let mirror_address = SUPERBLOCK_MIRROR_OFFSETS[mirror];
            for read_offset in pair_candidates(first, second, mirror_address)? {
                locations.push(SuperblockLocation {
                    read_offset,
                    mirror_address,
                });
            }
        }
        if locations.is_empty() {
            return Err(BtrfsError::ZonedSuperblockNotFound);
        }
        Ok(locations)
    }

    fn zone_at(&self, start: u64) -> Option<BtrfsZone> {
        self.zones
            .binary_search_by_key(&start, BtrfsZone::start)
            .ok()
            .map(|index| self.zones[index])
    }
}

/// Reader and optional zoned geometry for one Btrfs member.
pub struct BtrfsDeviceSource<R> {
    reader: R,
    zoned: Option<BtrfsZonedDevice>,
}

impl<R> BtrfsDeviceSource<R> {
    /// Wrap an ordinary file or non-zoned block-device reader.
    #[must_use]
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            zoned: None,
        }
    }

    /// Attach authoritative zoned-device geometry.
    #[must_use]
    pub fn with_zoned_device(mut self, zoned: BtrfsZonedDevice) -> Self {
        self.zoned = Some(zoned);
        self
    }

    pub(crate) fn into_parts(self) -> (R, Option<BtrfsZonedDevice>) {
        (self.reader, self.zoned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SuperblockLocation {
    pub(super) read_offset: u64,
    pub(super) mirror_address: u64,
}

fn validate_zone(zone: BtrfsZone, zone_size: u64) -> Result<()> {
    let end = zone
        .start
        .checked_add(zone.length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if !zone.start.is_multiple_of(zone_size)
        || zone.length != zone_size
        || zone.capacity == 0
        || zone.capacity > zone.length
        || !(zone.start..=end).contains(&zone.write_pointer)
    {
        return Err(BtrfsError::InvalidZoneGeometry { start: zone.start });
    }
    Ok(())
}

fn pair_candidates(first: BtrfsZone, second: BtrfsZone, mirror_address: u64) -> Result<Vec<u64>> {
    if first.zone_type.is_conventional() {
        if !second.zone_type.is_conventional() {
            return Err(BtrfsError::InvalidZoneGeometry { start: first.start });
        }
        return Ok(alloc::vec![first.start]);
    }
    if second.zone_type.is_conventional() {
        return Err(BtrfsError::InvalidZoneGeometry {
            start: second.start,
        });
    }

    let first_empty = first.condition == BtrfsZoneCondition::Empty;
    let second_empty = second.condition == BtrfsZoneCondition::Empty;
    let first_full = zone_is_full(first)?;
    let second_full = zone_is_full(second)?;
    if first_empty && second_empty {
        return Ok(Vec::new());
    }
    if first_full && second_full {
        return Ok(alloc::vec![
            final_superblock(first)?,
            final_superblock(second)?
        ]);
    }

    let next_write = if !first_full && (second_empty || second_full) {
        first.write_pointer
    } else if first_full {
        second.write_pointer
    } else {
        return Err(BtrfsError::InvalidZonedSuperblockLogState {
            mirror: mirror_address,
        });
    };
    let previous_end = if next_write == first.start {
        usable_end(second)?
    } else if next_write == second.start {
        usable_end(first)?
    } else {
        next_write
    };
    let superblock_size =
        u64::try_from(SUPERBLOCK_SIZE).map_err(|_| BtrfsError::IntegerOverflow)?;
    let read_offset = previous_end.checked_sub(superblock_size).ok_or(
        BtrfsError::InvalidZonedSuperblockLogState {
            mirror: mirror_address,
        },
    )?;
    if read_offset % superblock_size != 0 {
        return Err(BtrfsError::InvalidZonedSuperblockLogState {
            mirror: mirror_address,
        });
    }
    Ok(alloc::vec![read_offset])
}

fn zone_is_full(zone: BtrfsZone) -> Result<bool> {
    if zone.condition == BtrfsZoneCondition::Full {
        return Ok(true);
    }
    let superblock_size =
        u64::try_from(SUPERBLOCK_SIZE).map_err(|_| BtrfsError::IntegerOverflow)?;
    let next_end = zone
        .write_pointer
        .checked_add(superblock_size)
        .ok_or(BtrfsError::IntegerOverflow)?;
    Ok(next_end > usable_end(zone)?)
}

fn final_superblock(zone: BtrfsZone) -> Result<u64> {
    let superblock_size =
        u64::try_from(SUPERBLOCK_SIZE).map_err(|_| BtrfsError::IntegerOverflow)?;
    align_down(usable_end(zone)?, superblock_size)
        .checked_sub(superblock_size)
        .ok_or(BtrfsError::InvalidZoneGeometry { start: zone.start })
}

fn usable_end(zone: BtrfsZone) -> Result<u64> {
    zone.start
        .checked_add(zone.capacity)
        .ok_or(BtrfsError::IntegerOverflow)
}

const fn align_down(value: u64, alignment: u64) -> u64 {
    value - value % alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE_SIZE: u64 = MIN_ZONE_SIZE;

    fn zone(start: u64, write_pointer: u64, condition: BtrfsZoneCondition) -> BtrfsZone {
        BtrfsZone::new(
            start,
            ZONE_SIZE,
            ZONE_SIZE,
            write_pointer,
            BtrfsZoneType::SequentialWriteRequired,
            condition,
        )
    }

    #[test]
    fn in_use_first_zone_selects_previous_record() {
        let first = zone(0, 3 * 4096, BtrfsZoneCondition::Closed);
        let second = zone(ZONE_SIZE, ZONE_SIZE, BtrfsZoneCondition::Empty);
        assert_eq!(
            pair_candidates(first, second, SUPERBLOCK_MIRROR_OFFSETS[0]).expect("locations"),
            [2 * 4096]
        );
    }

    #[test]
    fn full_first_zone_wraps_from_empty_second_zone() {
        let first = zone(0, ZONE_SIZE, BtrfsZoneCondition::Full);
        let second = zone(ZONE_SIZE, ZONE_SIZE, BtrfsZoneCondition::Empty);
        assert_eq!(
            pair_candidates(first, second, SUPERBLOCK_MIRROR_OFFSETS[0]).expect("locations"),
            [ZONE_SIZE - 4096]
        );
    }

    #[test]
    fn both_full_zones_expose_both_generation_candidates() {
        let first = zone(0, ZONE_SIZE, BtrfsZoneCondition::Full);
        let second = zone(ZONE_SIZE, 2 * ZONE_SIZE, BtrfsZoneCondition::Full);
        assert_eq!(
            pair_candidates(first, second, SUPERBLOCK_MIRROR_OFFSETS[0]).expect("locations"),
            [ZONE_SIZE - 4096, 2 * ZONE_SIZE - 4096]
        );
    }

    #[test]
    fn two_active_zones_are_an_invalid_log_state() {
        let first = zone(0, 4096, BtrfsZoneCondition::Closed);
        let second = zone(ZONE_SIZE, ZONE_SIZE + 4096, BtrfsZoneCondition::Closed);
        assert!(matches!(
            pair_candidates(first, second, SUPERBLOCK_MIRROR_OFFSETS[0]),
            Err(BtrfsError::InvalidZonedSuperblockLogState { .. })
        ));
    }

    #[test]
    fn zone_geometry_rejects_overlap_and_bad_sizes() {
        assert!(matches!(
            BtrfsZonedDevice::new(1024, Vec::new()),
            Err(BtrfsError::InvalidZoneSize { .. })
        ));
        let bad = BtrfsZone::new(
            1,
            ZONE_SIZE,
            ZONE_SIZE,
            1,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Empty,
        );
        assert!(matches!(
            BtrfsZonedDevice::new(ZONE_SIZE, alloc::vec![bad]),
            Err(BtrfsError::InvalidZoneGeometry { .. })
        ));
    }
}
