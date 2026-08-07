//! Linux block-zone reporting through `BLKGETZONESZ` and `BLKREPORTZONE`.

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;

use fsmnt_device::{
    BlockZone, BlockZoneCondition, BlockZoneReporter, BlockZoneType, HostDriveError,
    HostDriveResult,
};

use crate::drives::open_device;

const KERNEL_SECTOR_SIZE: u64 = 512;
const MAX_REPORT_ZONES: usize = 64;
const BLK_ZONE_REP_CAPACITY: u32 = 1;

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct RawBlockZone {
    start: u64,
    length: u64,
    write_pointer: u64,
    zone_type: u8,
    condition: u8,
    _non_sequential: u8,
    _reset_recommended: u8,
    _reserved_alignment: [u8; 4],
    capacity: u64,
    _reserved: [u8; 24],
}

#[repr(C)]
struct RawZoneReport {
    sector: u64,
    zone_count: u32,
    flags: u32,
    zones: [RawBlockZone; MAX_REPORT_ZONES],
}

const _: [(); 64] = [(); size_of::<RawBlockZone>()];
const _: [(); 16] = [(); std::mem::offset_of!(RawZoneReport, zones)];

pub(crate) fn reporter_for_path(
    path: &str,
    base_offset: u64,
    length: u64,
) -> HostDriveResult<Option<Box<dyn BlockZoneReporter>>> {
    let file = open_device(path)?;
    LinuxZoneReporter::new(file, base_offset, length)
        .map(|reporter| reporter.map(|value| Box::new(value) as Box<dyn BlockZoneReporter>))
        .map_err(HostDriveError::Io)
}

struct LinuxZoneReporter {
    file: File,
    base_offset: u64,
    length: u64,
    zone_size: u64,
}

impl LinuxZoneReporter {
    fn new(file: File, base_offset: u64, length: u64) -> io::Result<Option<Self>> {
        let mut zone_sectors = 0_u32;
        let request = libc::c_ulong::from(linux_raw_sys::ioctl::BLKGETZONESZ);
        // SAFETY: `file` owns a live block-device descriptor and
        // `zone_sectors` is a writable `u32`, matching the ioctl ABI.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), request, &raw mut zone_sectors) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) {
                return Ok(None);
            }
            return Err(error);
        }
        if zone_sectors == 0 {
            return Ok(None);
        }
        let zone_size = u64::from(zone_sectors)
            .checked_mul(KERNEL_SECTOR_SIZE)
            .ok_or_else(|| io::Error::other("Linux zone size overflowed"))?;
        Ok(Some(Self {
            file,
            base_offset,
            length,
            zone_size,
        }))
    }

    fn report(&self, start: u64, maximum: usize) -> io::Result<Vec<BlockZone>> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let physical_start = self
            .base_offset
            .checked_add(start)
            .ok_or_else(|| io::Error::other("zone-report offset overflowed"))?;
        if physical_start % KERNEL_SECTOR_SIZE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zone-report offset is not 512-byte aligned",
            ));
        }
        let requested = maximum.min(MAX_REPORT_ZONES);
        let mut report = RawZoneReport {
            sector: physical_start / KERNEL_SECTOR_SIZE,
            zone_count: u32::try_from(requested)
                .map_err(|_| io::Error::other("zone-report count does not fit u32"))?,
            flags: 0,
            zones: [RawBlockZone::default(); MAX_REPORT_ZONES],
        };
        let request = libc::c_ulong::from(linux_raw_sys::ioctl::BLKREPORTZONE);
        // SAFETY: `file` owns a live block-device descriptor. `report` begins
        // with the exact `blk_zone_report` ABI header and provides storage for
        // `zone_count` consecutive 64-byte `blk_zone` records.
        let result = unsafe { libc::ioctl(self.file.as_raw_fd(), request, &raw mut report) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let reported = usize::try_from(report.zone_count)
            .map_err(|_| io::Error::other("reported zone count does not fit usize"))?;
        if reported > requested {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned more zones than requested",
            ));
        }
        report.zones[..reported]
            .iter()
            .map(|zone| self.decode_zone(*zone, report.flags))
            .collect()
    }

    fn decode_zone(&self, raw: RawBlockZone, report_flags: u32) -> io::Result<BlockZone> {
        let physical_start = sectors_to_bytes(raw.start)?;
        let start = physical_start
            .checked_sub(self.base_offset)
            .ok_or_else(|| io::Error::other("reported zone begins before the member"))?;
        if self.length != u64::MAX && start >= self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reported zone begins beyond the member",
            ));
        }
        let length = sectors_to_bytes(raw.length)?;
        let capacity = if report_flags & BLK_ZONE_REP_CAPACITY == 0 {
            length
        } else {
            sectors_to_bytes(raw.capacity)?
        };
        let zone_type = decode_zone_type(raw.zone_type)?;
        let write_pointer = if zone_type == BlockZoneType::Conventional {
            start
        } else {
            sectors_to_bytes(raw.write_pointer)?
                .checked_sub(self.base_offset)
                .ok_or_else(|| io::Error::other("zone write pointer precedes the member"))?
        };
        Ok(BlockZone::new(
            start,
            length,
            capacity,
            write_pointer,
            zone_type,
            decode_zone_condition(raw.condition)?,
        ))
    }
}

impl BlockZoneReporter for LinuxZoneReporter {
    fn zone_size(&self) -> u64 {
        self.zone_size
    }

    fn report_zones(&self, start: u64, maximum: usize) -> io::Result<Vec<BlockZone>> {
        self.report(start, maximum)
    }
}

fn sectors_to_bytes(sectors: u64) -> io::Result<u64> {
    sectors
        .checked_mul(KERNEL_SECTOR_SIZE)
        .ok_or_else(|| io::Error::other("Linux zone coordinate overflowed"))
}

fn decode_zone_type(value: u8) -> io::Result<BlockZoneType> {
    match value {
        0x1 => Ok(BlockZoneType::Conventional),
        0x2 => Ok(BlockZoneType::SequentialWriteRequired),
        0x3 => Ok(BlockZoneType::SequentialWritePreferred),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown Linux block-zone type {value:#x}"),
        )),
    }
}

fn decode_zone_condition(value: u8) -> io::Result<BlockZoneCondition> {
    match value {
        0x0 => Ok(BlockZoneCondition::NotWritePointer),
        0x1 => Ok(BlockZoneCondition::Empty),
        0x2 => Ok(BlockZoneCondition::ImplicitOpen),
        0x3 => Ok(BlockZoneCondition::ExplicitOpen),
        0x4 => Ok(BlockZoneCondition::Closed),
        0x0d => Ok(BlockZoneCondition::ReadOnly),
        0x0e => Ok(BlockZoneCondition::Full),
        0x0f => Ok(BlockZoneCondition::Offline),
        0xff => Ok(BlockZoneCondition::Active),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown Linux block-zone condition {value:#x}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_zone_layout_matches_linux_uapi() {
        assert_eq!(size_of::<RawBlockZone>(), 64);
        assert_eq!(std::mem::offset_of!(RawZoneReport, zones), 16);
    }

    #[test]
    fn every_linux_zone_enum_value_is_typed() {
        for value in [0x1, 0x2, 0x3] {
            decode_zone_type(value).expect("known zone type");
        }
        for value in [0x0, 0x1, 0x2, 0x3, 0x4, 0x0d, 0x0e, 0x0f, 0xff] {
            decode_zone_condition(value).expect("known zone condition");
        }
        assert!(decode_zone_type(0).is_err());
        assert!(decode_zone_condition(5).is_err());
    }
}
