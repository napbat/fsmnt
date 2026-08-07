use thiserror::Error;

use crate::DeviceReader;

use super::{BlockZoneReporter, LogicalVolumeId, PhysicalExtent};

/// Identity and provenance of one readable block source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceMemberId {
    /// Direct physical partition extent.
    Physical(PhysicalExtent),
    /// Operating-system logical volume.
    Logical(LogicalVolumeId),
    /// Caller-defined source such as an image or assembled mapping.
    Synthetic(String),
}

/// One readable member of a filesystem or storage volume.
pub struct DeviceMember {
    identity: SourceMemberId,
    reader: Box<dyn DeviceReader>,
    length: u64,
    sector_size: u32,
    zone_reporter: Option<Box<dyn BlockZoneReporter>>,
}

impl DeviceMember {
    /// Create a device member with its source geometry.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSetError::InvalidSectorSize`] when `sector_size` is
    /// zero or not a power of two.
    pub fn new(
        identity: SourceMemberId,
        reader: Box<dyn DeviceReader>,
        length: u64,
        sector_size: u32,
    ) -> Result<Self, DeviceSetError> {
        if sector_size == 0 || !sector_size.is_power_of_two() {
            return Err(DeviceSetError::InvalidSectorSize { sector_size });
        }
        Ok(Self {
            identity,
            reader,
            length,
            sector_size,
            zone_reporter: None,
        })
    }

    /// Attach sparse block-zone reporting for this member.
    #[must_use]
    pub fn with_zone_reporter(mut self, reporter: Box<dyn BlockZoneReporter>) -> Self {
        self.zone_reporter = Some(reporter);
        self
    }

    /// Source identity.
    #[must_use]
    pub const fn identity(&self) -> &SourceMemberId {
        &self.identity
    }

    /// Readable length in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Logical sector size in bytes.
    #[must_use]
    pub const fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Sparse zone reporter for a zoned block device, when available.
    #[must_use]
    pub fn zone_reporter(&self) -> Option<&dyn BlockZoneReporter> {
        self.zone_reporter.as_deref()
    }

    /// Shared reader access.
    #[must_use]
    pub fn reader(&self) -> &dyn DeviceReader {
        self.reader.as_ref()
    }

    /// Mutable reader access.
    pub fn reader_mut(&mut self) -> &mut dyn DeviceReader {
        self.reader.as_mut()
    }

    /// Consume the member and return its reader.
    #[must_use]
    pub fn into_reader(self) -> Box<dyn DeviceReader> {
        self.reader
    }
}

/// An ordered collection of raw members, with the selected partition first.
pub struct DeviceSet {
    primary: DeviceMember,
    additional: Vec<DeviceMember>,
}

impl DeviceSet {
    /// Start a device set with its primary member.
    #[must_use]
    pub fn new(primary: DeviceMember) -> Self {
        Self {
            primary,
            additional: Vec::new(),
        }
    }

    /// Add another raw member.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSetError::DuplicateMember`] if the same source
    /// identity is already present.
    pub fn push(&mut self, member: DeviceMember) -> Result<(), DeviceSetError> {
        if self
            .members()
            .any(|existing| existing.identity() == member.identity())
        {
            return Err(DeviceSetError::DuplicateMember {
                identity: member.identity().clone(),
            });
        }
        self.additional.push(member);
        Ok(())
    }

    /// Number of members in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.additional.len().saturating_add(1)
    }

    /// Device sets always contain a primary member.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Primary member selected by the caller.
    #[must_use]
    pub const fn primary(&self) -> &DeviceMember {
        &self.primary
    }

    /// Mutable access to the primary member.
    pub const fn primary_mut(&mut self) -> &mut DeviceMember {
        &mut self.primary
    }

    /// Iterate over all members, with the primary member first.
    pub fn members(&self) -> impl Iterator<Item = &DeviceMember> {
        std::iter::once(&self.primary).chain(self.additional.iter())
    }

    /// Consume the set and return all members.
    #[must_use]
    pub fn into_members(self) -> Vec<DeviceMember> {
        let mut members = Vec::with_capacity(self.len());
        members.push(self.primary);
        members.extend(self.additional);
        members
    }

    /// Consume a single-member set and return its reader.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSetError::MultipleMembers`] when additional members
    /// are present and the consumer has not implemented multi-device access.
    pub fn into_single_reader(self) -> Result<Box<dyn DeviceReader>, DeviceSetError> {
        if !self.additional.is_empty() {
            return Err(DeviceSetError::MultipleMembers { actual: self.len() });
        }
        Ok(self.primary.into_reader())
    }
}

/// Invalid device-set geometry or unsupported cardinality.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DeviceSetError {
    /// Logical sector size was zero or not a power of two.
    #[error("invalid logical sector size {sector_size}")]
    InvalidSectorSize {
        /// Invalid sector size.
        sector_size: u32,
    },
    /// A single-device consumer received several members.
    #[error("filesystem driver does not support {actual} device members")]
    MultipleMembers {
        /// Actual number of supplied members.
        actual: usize,
    },
    /// A source identity appeared more than once.
    #[error("device member {identity:?} was supplied more than once")]
    DuplicateMember {
        /// Repeated source identity.
        identity: SourceMemberId,
    },
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn member(id: &str) -> DeviceMember {
        DeviceMember::new(
            SourceMemberId::Synthetic(id.to_string()),
            Box::new(Cursor::new(vec![0_u8; 16])),
            16,
            512,
        )
        .expect("member")
    }

    #[test]
    fn single_member_can_be_unwrapped() {
        assert!(DeviceSet::new(member("one")).into_single_reader().is_ok());
    }

    #[test]
    fn multiple_members_require_an_aware_consumer() {
        let mut devices = DeviceSet::new(member("one"));
        devices.push(member("two")).expect("second member");
        assert_eq!(
            devices.into_single_reader().err(),
            Some(DeviceSetError::MultipleMembers { actual: 2 })
        );
    }

    #[test]
    fn sector_size_is_validated() {
        let result = DeviceMember::new(
            SourceMemberId::Synthetic("bad".to_string()),
            Box::new(Cursor::new(Vec::<u8>::new())),
            0,
            1000,
        );
        assert!(matches!(
            result,
            Err(DeviceSetError::InvalidSectorSize { sector_size: 1000 })
        ));
    }

    #[test]
    fn duplicate_member_identity_is_rejected() {
        let mut devices = DeviceSet::new(member("one"));
        assert!(matches!(
            devices.push(member("one")),
            Err(DeviceSetError::DuplicateMember { .. })
        ));
    }
}
