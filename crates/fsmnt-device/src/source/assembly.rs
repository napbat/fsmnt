use std::io::{Error, ErrorKind, Result};

use nostdio::{Read, Seek, SeekFrom};
use thiserror::Error;

use super::{DeviceMember, DeviceSet};

/// Supported mappings from several raw members into one logical byte space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawVolumeLayout {
    /// Concatenate members in their supplied order.
    Linear,
    /// Interleave fixed-size stripes across every member.
    Striped {
        /// Stripe unit in bytes.
        stripe_size: u64,
        /// Exposed logical length in bytes.
        length: u64,
    },
    /// Read identical logical offsets from interchangeable replicas.
    Mirrored {
        /// Exposed logical length in bytes.
        length: u64,
    },
}

/// A logical reader assembled from one or more raw members.
pub struct AssembledVolume {
    inner: AssembledVolumeKind,
}

enum AssembledVolumeKind {
    Linear(LinearVolume),
    Striped(StripedVolume),
    Mirrored(MirroredVolume),
}

impl AssembledVolume {
    /// Logical length in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        match &self.inner {
            AssembledVolumeKind::Linear(volume) => volume.length,
            AssembledVolumeKind::Striped(volume) => volume.length,
            AssembledVolumeKind::Mirrored(volume) => volume.length,
        }
    }

    /// Logical sector size shared by all members.
    #[must_use]
    pub const fn sector_size(&self) -> u32 {
        match &self.inner {
            AssembledVolumeKind::Linear(volume) => volume.sector_size,
            AssembledVolumeKind::Striped(volume) => volume.sector_size,
            AssembledVolumeKind::Mirrored(volume) => volume.sector_size,
        }
    }
}

impl Read for AssembledVolume {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        match &mut self.inner {
            AssembledVolumeKind::Linear(volume) => volume.read(buffer),
            AssembledVolumeKind::Striped(volume) => volume.read(buffer),
            AssembledVolumeKind::Mirrored(volume) => volume.read(buffer),
        }
    }
}

impl Seek for AssembledVolume {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        match &mut self.inner {
            AssembledVolumeKind::Linear(volume) => volume.seek(position),
            AssembledVolumeKind::Striped(volume) => volume.seek(position),
            AssembledVolumeKind::Mirrored(volume) => volume.seek(position),
        }
    }
}

/// Construct a logical reader for `layout` from `devices`.
///
/// This is the storage-volume path: a volume-manager parser derives the
/// mapping and then hands the assembled reader to an ordinary single-device
/// filesystem driver. Filesystems that own their multi-device mapping, such
/// as Btrfs, receive the unassembled [`DeviceSet`] through
/// [`FilesystemDriver::open_devices`](crate::FilesystemDriver::open_devices)
/// instead.
///
/// # Errors
///
/// Returns [`RawAssemblyError`] when member geometry cannot represent the
/// requested layout or logical length.
pub fn assemble_raw_volume(
    devices: DeviceSet,
    layout: RawVolumeLayout,
) -> std::result::Result<AssembledVolume, RawAssemblyError> {
    let sector_size = common_sector_size(&devices)?;
    let members = devices.into_members();
    match layout {
        RawVolumeLayout::Linear => {
            let length = members
                .iter()
                .try_fold(0_u64, |total, member| total.checked_add(member.length()));
            let Some(length) = length else {
                return Err(RawAssemblyError::CapacityOverflow);
            };
            Ok(AssembledVolume {
                inner: AssembledVolumeKind::Linear(LinearVolume {
                    members,
                    position: 0,
                    length,
                    sector_size,
                }),
            })
        }
        RawVolumeLayout::Striped {
            stripe_size,
            length,
        } => {
            if stripe_size == 0 {
                return Err(RawAssemblyError::InvalidStripeSize);
            }
            let shortest = members
                .iter()
                .map(DeviceMember::length)
                .fold(u64::MAX, u64::min);
            let complete_member_bytes = shortest - (shortest % stripe_size);
            let member_count =
                u64::try_from(members.len()).map_err(|_| RawAssemblyError::CapacityOverflow)?;
            let capacity = complete_member_bytes
                .checked_mul(member_count)
                .ok_or(RawAssemblyError::CapacityOverflow)?;
            if length > capacity {
                return Err(RawAssemblyError::LengthExceedsCapacity { length, capacity });
            }
            Ok(AssembledVolume {
                inner: AssembledVolumeKind::Striped(StripedVolume {
                    members,
                    position: 0,
                    length,
                    sector_size,
                    stripe_size,
                }),
            })
        }
        RawVolumeLayout::Mirrored { length } => {
            let capacity = members
                .iter()
                .map(DeviceMember::length)
                .fold(u64::MAX, u64::min);
            if length > capacity {
                return Err(RawAssemblyError::LengthExceedsCapacity { length, capacity });
            }
            Ok(AssembledVolume {
                inner: AssembledVolumeKind::Mirrored(MirroredVolume {
                    members,
                    position: 0,
                    length,
                    sector_size,
                }),
            })
        }
    }
}

fn common_sector_size(devices: &DeviceSet) -> std::result::Result<u32, RawAssemblyError> {
    let sector_size = devices.primary().sector_size();
    if let Some(member) = devices
        .members()
        .find(|member| member.sector_size() != sector_size)
    {
        return Err(RawAssemblyError::SectorSizeMismatch {
            expected: sector_size,
            actual: member.sector_size(),
        });
    }
    Ok(sector_size)
}

/// Invalid or unsupported raw-member geometry.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RawAssemblyError {
    /// Member capacities overflow the logical address type.
    #[error("raw member capacity exceeds u64")]
    CapacityOverflow,
    /// A striped layout specified a zero-byte stripe.
    #[error("stripe size must be non-zero")]
    InvalidStripeSize,
    /// Requested logical size exceeds what the supplied members can provide.
    #[error("logical length {length} exceeds assembled capacity {capacity}")]
    LengthExceedsCapacity {
        /// Requested logical length.
        length: u64,
        /// Maximum safe logical capacity.
        capacity: u64,
    },
    /// Members disagree about their logical sector size.
    #[error("member sector size {actual} does not match {expected}")]
    SectorSizeMismatch {
        /// Sector size established by the primary member.
        expected: u32,
        /// Conflicting sector size.
        actual: u32,
    },
}

struct LinearVolume {
    members: Vec<DeviceMember>,
    position: u64,
    length: u64,
    sector_size: u32,
}

impl Read for LinearVolume {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }

        let mut filled = 0;
        while filled < buffer.len() && self.position < self.length {
            let (member_index, member_offset) = linear_location(&self.members, self.position)
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "linear member missing"))?;
            let member = &mut self.members[member_index];
            let member_remaining = member.length().saturating_sub(member_offset);
            let volume_remaining = self.length.saturating_sub(self.position);
            let buffer_remaining = buffer.len() - filled;
            let amount = bounded_read_length(member_remaining, volume_remaining, buffer_remaining);

            member.reader_mut().seek(SeekFrom::Start(member_offset))?;
            let read = member
                .reader_mut()
                .read(&mut buffer[filled..filled + amount])?;
            if read == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "linear member ended before its declared length",
                ));
            }
            let read_u64 = u64::try_from(read).map_err(|_| Error::other("read size overflow"))?;
            self.position = self
                .position
                .checked_add(read_u64)
                .ok_or_else(|| Error::other("logical position overflow"))?;
            filled += read;
        }
        Ok(filled)
    }
}

impl Seek for LinearVolume {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        self.position = resolve_seek(self.position, self.length, position)?;
        Ok(self.position)
    }
}

fn linear_location(members: &[DeviceMember], logical_offset: u64) -> Option<(usize, u64)> {
    let mut base = 0_u64;
    for (index, member) in members.iter().enumerate() {
        let end = base.checked_add(member.length())?;
        if logical_offset < end {
            return Some((index, logical_offset - base));
        }
        base = end;
    }
    None
}

struct StripedVolume {
    members: Vec<DeviceMember>,
    position: u64,
    length: u64,
    sector_size: u32,
    stripe_size: u64,
}

impl Read for StripedVolume {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }

        let member_count =
            u64::try_from(self.members.len()).map_err(|_| Error::other("member count overflow"))?;
        let mut filled = 0;
        while filled < buffer.len() && self.position < self.length {
            let stripe = self.position / self.stripe_size;
            let within_stripe = self.position % self.stripe_size;
            let member_index_u64 = stripe % member_count;
            let member_index = usize::try_from(member_index_u64)
                .map_err(|_| Error::other("member index overflow"))?;
            let member_stripe = stripe / member_count;
            let member_offset = member_stripe
                .checked_mul(self.stripe_size)
                .and_then(|offset| offset.checked_add(within_stripe))
                .ok_or_else(|| Error::other("striped member offset overflow"))?;
            let stripe_remaining = self.stripe_size - within_stripe;
            let volume_remaining = self.length - self.position;
            let buffer_remaining = buffer.len() - filled;
            let amount = bounded_read_length(stripe_remaining, volume_remaining, buffer_remaining);

            let member = &mut self.members[member_index];
            member.reader_mut().seek(SeekFrom::Start(member_offset))?;
            let read = member
                .reader_mut()
                .read(&mut buffer[filled..filled + amount])?;
            if read == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "striped member ended before its declared length",
                ));
            }
            let read_u64 = u64::try_from(read).map_err(|_| Error::other("read size overflow"))?;
            self.position = self
                .position
                .checked_add(read_u64)
                .ok_or_else(|| Error::other("logical position overflow"))?;
            filled += read;
        }
        Ok(filled)
    }
}

impl Seek for StripedVolume {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        self.position = resolve_seek(self.position, self.length, position)?;
        Ok(self.position)
    }
}

struct MirroredVolume {
    members: Vec<DeviceMember>,
    position: u64,
    length: u64,
    sector_size: u32,
}

impl Read for MirroredVolume {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let amount = bounded_read_length(
            self.length - self.position,
            self.length - self.position,
            buffer.len(),
        );
        let mut last_error = None;

        for member in &mut self.members {
            if let Err(error) = member.reader_mut().seek(SeekFrom::Start(self.position)) {
                last_error = Some(error);
                continue;
            }
            match member.reader_mut().read(&mut buffer[..amount]) {
                Ok(0) => {
                    last_error = Some(Error::new(
                        ErrorKind::UnexpectedEof,
                        "mirror member ended before its declared length",
                    ));
                }
                Ok(read) => {
                    let read_u64 =
                        u64::try_from(read).map_err(|_| Error::other("read size overflow"))?;
                    self.position = self
                        .position
                        .checked_add(read_u64)
                        .ok_or_else(|| Error::other("logical position overflow"))?;
                    return Ok(read);
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| Error::other("mirrored volume has no members")))
    }
}

impl Seek for MirroredVolume {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        self.position = resolve_seek(self.position, self.length, position)?;
        Ok(self.position)
    }
}

fn bounded_read_length(first: u64, second: u64, buffer_length: usize) -> usize {
    let buffer_u64 = u64::try_from(buffer_length).unwrap_or(u64::MAX);
    usize::try_from(first.min(second).min(buffer_u64)).unwrap_or(buffer_length)
}

fn resolve_seek(current: u64, length: u64, position: SeekFrom) -> Result<u64> {
    let resolved = match position {
        SeekFrom::Start(offset) => Some(offset),
        SeekFrom::Current(offset) => add_signed(current, offset),
        SeekFrom::End(offset) => add_signed(length, offset),
    };
    resolved.ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid logical seek"))
}

fn add_signed(base: u64, offset: i64) -> Option<u64> {
    if offset.is_negative() {
        base.checked_sub(offset.unsigned_abs())
    } else {
        base.checked_add(u64::try_from(offset).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::source::{DeviceMember, SourceMemberId};

    fn member(id: &str, bytes: &[u8]) -> DeviceMember {
        DeviceMember::new(
            SourceMemberId::Synthetic(id.to_string()),
            Box::new(Cursor::new(bytes.to_vec())),
            u64::try_from(bytes.len()).expect("test member length fits u64"),
            512,
        )
        .expect("member")
    }

    fn devices(parts: &[(&str, &[u8])]) -> DeviceSet {
        let mut parts = parts.iter();
        let (id, bytes) = parts.next().expect("at least one member");
        let mut set = DeviceSet::new(member(id, bytes));
        for (id, bytes) in parts {
            set.push(member(id, bytes)).expect("unique test member");
        }
        set
    }

    #[test]
    fn linear_mapping_reads_across_members() {
        let mut volume = assemble_raw_volume(
            devices(&[("one", b"abcd"), ("two", b"EFGH")]),
            RawVolumeLayout::Linear,
        )
        .expect("linear volume");
        let mut bytes = [0_u8; 6];
        volume.seek(SeekFrom::Start(2)).expect("seek");
        volume.read_exact(&mut bytes).expect("read");
        assert_eq!(&bytes, b"cdEFGH");
    }

    #[test]
    fn striped_mapping_interleaves_stripes() {
        let mut volume = assemble_raw_volume(
            devices(&[("one", b"aaaacccc"), ("two", b"bbbbdddd")]),
            RawVolumeLayout::Striped {
                stripe_size: 4,
                length: 16,
            },
        )
        .expect("striped volume");
        let mut bytes = [0_u8; 16];
        volume.read_exact(&mut bytes).expect("read");
        assert_eq!(&bytes, b"aaaabbbbccccdddd");
    }

    #[test]
    fn mirrored_mapping_reads_replica() {
        let mut volume = assemble_raw_volume(
            devices(&[("one", b"mirror"), ("two", b"mirror")]),
            RawVolumeLayout::Mirrored { length: 6 },
        )
        .expect("mirrored volume");
        let mut bytes = [0_u8; 6];
        volume.read_exact(&mut bytes).expect("read");
        assert_eq!(&bytes, b"mirror");
    }

    #[test]
    fn stripe_capacity_is_validated() {
        let result = assemble_raw_volume(
            devices(&[("one", b"aaaa"), ("two", b"bbbb")]),
            RawVolumeLayout::Striped {
                stripe_size: 4,
                length: 9,
            },
        );
        assert!(matches!(
            result,
            Err(RawAssemblyError::LengthExceedsCapacity {
                length: 9,
                capacity: 8
            })
        ));
    }
}
