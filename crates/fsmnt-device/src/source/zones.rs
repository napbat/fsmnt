use std::io;

/// Write-ordering model reported for one block-device zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockZoneType {
    /// Random writes are permitted and there is no meaningful write pointer.
    Conventional,
    /// Every write must begin at the current write pointer.
    SequentialWriteRequired,
    /// Sequential writes are preferred, but random writes are permitted.
    SequentialWritePreferred,
}

/// Current state reported for one block-device zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockZoneCondition {
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

/// Geometry and write state of one block-device zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockZone {
    start: u64,
    length: u64,
    capacity: u64,
    write_pointer: u64,
    zone_type: BlockZoneType,
    condition: BlockZoneCondition,
}

impl BlockZone {
    /// Describe one zone using byte offsets relative to its exposed device
    /// member.
    #[must_use]
    pub const fn new(
        start: u64,
        length: u64,
        capacity: u64,
        write_pointer: u64,
        zone_type: BlockZoneType,
        condition: BlockZoneCondition,
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

    /// Byte offset at which the zone begins.
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

    /// Current write pointer as a byte offset relative to the device member.
    #[must_use]
    pub const fn write_pointer(&self) -> u64 {
        self.write_pointer
    }

    /// Write-ordering model for the zone.
    #[must_use]
    pub const fn zone_type(&self) -> BlockZoneType {
        self.zone_type
    }

    /// Current zone condition.
    #[must_use]
    pub const fn condition(&self) -> BlockZoneCondition {
        self.condition
    }
}

/// Sparse, on-demand access to a block device's zone report.
///
/// Coordinates returned by this trait are relative to the same member as the
/// associated [`crate::DeviceMember`] reader. Implementations should query only
/// the requested range rather than materializing every zone on a large device.
pub trait BlockZoneReporter: Send + Sync {
    /// Uniform zone size in bytes.
    fn zone_size(&self) -> u64;

    /// Report up to `maximum` zones beginning with the zone containing
    /// `start`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the device rejects the report or returns
    /// malformed geometry.
    fn report_zones(&self, start: u64, maximum: usize) -> io::Result<Vec<BlockZone>>;
}
