//! Turning a located extent into the device set a driver is handed.
//!
//! One filesystem is not always one partition: Btrfs spans several, and the
//! members can sit on drives the caller never named. Every way of locating a
//! partition ends here, so raw multi-member discovery, best-effort reads and
//! logical-volume selection behave the same whether the extent came from a
//! partition table, a scan, or a byte offset.

use std::io::{Read, Seek};
use std::sync::Arc;

use tracing::debug;

use fsmnt_device::{
    DeviceMember, DeviceReader, DeviceSet, DriverRegistry, FilesystemMemberId,
    FilesystemOpenOptions, HostDriveId, HostVolumeResolver, LogicalVolumeId, PartitionAddress,
    PartitionReader, PhysicalExtent, ReadSubstitutions, ResolvedMemberDiscovery, SectorReader,
    SourceMemberId, SourceOrigin, TolerantReader, select_logical_volume,
};

use super::{
    LocatedPartition, OpenedPartition, locate_partition, locate_partitions, whole_sectors,
};
use crate::layout::LayoutOrigin;
use crate::{ext_backup, truncation};

/// How member readers treat data the source cannot provide.
#[derive(Clone, Default)]
pub(super) struct ReadPolicy {
    /// When set, members zero-fill unreadable bytes and charge them here.
    substitutions: Option<Arc<ReadSubstitutions>>,
}

impl ReadPolicy {
    /// Count and zero-fill unreadable bytes, or fail the read as usual.
    pub(super) fn new(best_effort: bool) -> Self {
        Self {
            substitutions: best_effort.then(|| Arc::new(ReadSubstitutions::default())),
        }
    }

    /// Wrap a member's reader according to the policy.
    fn wrap<R: Read + Seek + Send + 'static>(
        &self,
        reader: R,
        length: u64,
    ) -> std::io::Result<Box<dyn DeviceReader>> {
        Ok(match &self.substitutions {
            Some(stats) => Box::new(TolerantReader::with_stats(
                reader,
                length,
                Arc::clone(stats),
            )?),
            None => Box::new(reader),
        })
    }
}

/// Open the operating system's logical view of a located partition.
pub(super) fn open_logical_partition<E: HostVolumeResolver>(
    located: &LocatedPartition,
    requested: Option<&LogicalVolumeId>,
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
    policy: &ReadPolicy,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let candidates = E::logical_volumes(&located.extent)?;
    debug!(
        drive = %located.extent.drive(),
        offset = located.extent.offset(),
        candidates = candidates.len(),
        requested = ?requested.map(LogicalVolumeId::as_str),
        "found the operating system's logical volumes over the partition"
    );
    let volume = select_logical_volume(&located.extent, &candidates, requested)?;
    let length = volume.length().unwrap_or_else(|| located.extent.length());
    let sector_size = volume.sector_size().unwrap_or(located.sector_size);
    let identity = volume.id().clone();
    debug!(
        volume = %identity,
        length,
        sector_size,
        "selected a logical volume to read the partition through"
    );
    let reader = E::open_logical_volume(&volume)?;
    let zone_reporter = E::logical_zone_reporter(&volume)?;
    let reader = SectorReader::new(reader, length, sector_size)?;
    let mut member = DeviceMember::new(
        SourceMemberId::Logical(identity),
        policy.wrap(reader, length)?,
        length,
        sector_size,
    )?;
    if let Some(zone_reporter) = zone_reporter {
        member = member.with_zone_reporter(zone_reporter);
    }
    open_devices(
        DeviceSet::new(member),
        SourceOrigin::Logical(volume),
        length,
        located.origin,
        drivers,
        filesystem,
        policy,
    )
}

/// Open a located partition raw, gathering any further members the
/// filesystem says it needs.
pub(super) fn open_raw_partitions<E: HostVolumeResolver>(
    primary: &LocatedPartition,
    additional: &[PartitionAddress],
    sector_size: Option<u32>,
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
    policy: &ReadPolicy,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let mut extents = Vec::with_capacity(additional.len().saturating_add(1));
    extents.push(primary.extent.clone());
    let mut primary_member = open_raw_member::<E>(primary, policy)?;
    let primary_discovery = discover_member(drivers, &mut primary_member)?;
    let mut discovered_ids = primary_discovery
        .as_ref()
        .map(|resolved| vec![resolved.discovery().member().clone()])
        .unwrap_or_default();
    let mut devices = DeviceSet::new(primary_member);

    for address in additional {
        let located = locate_partition::<E>(address.drive(), address.partition(), sector_size)?;
        let mut member = open_raw_member::<E>(&located, policy)?;
        if let (Some(primary), Some(candidate)) = (
            primary_discovery.as_ref(),
            discover_member(drivers, &mut member)?,
        ) && member_matches(primary, &candidate, &discovered_ids)
        {
            discovered_ids.push(candidate.discovery().member().clone());
        }
        extents.push(located.extent.clone());
        devices.push(member)?;
    }

    if let Some(discovery) = primary_discovery.as_ref() {
        discover_raw_partitions::<E>(
            primary.extent.drive(),
            discovery,
            &mut discovered_ids,
            &mut devices,
            &mut extents,
            drivers,
            policy,
        );
    }

    debug!(
        drive = %primary.extent.drive(),
        offset = primary.extent.offset(),
        members = extents.len(),
        stated = additional.len(),
        "assembled the raw device set the filesystem will be opened from"
    );

    let size = if extents.len() == 1 {
        primary.extent.length()
    } else {
        0
    };
    open_devices(
        devices,
        SourceOrigin::Raw(extents),
        size,
        primary.origin,
        drivers,
        filesystem,
        policy,
    )
}

fn discover_member(
    drivers: &DriverRegistry,
    member: &mut DeviceMember,
) -> Result<Option<ResolvedMemberDiscovery>, Box<dyn std::error::Error>> {
    let detected = fsmnt_device::detect_boot_sector_at(member.reader_mut(), 0);
    let restored = std::io::Seek::seek(member.reader_mut(), std::io::SeekFrom::Start(0));
    let detected = match (detected, restored) {
        (Ok(detected), Ok(_)) => detected,
        (Err(error), _) | (Ok(_), Err(error)) => return Err(error.into()),
    };
    Ok(drivers.discover_members(member, detected)?)
}

fn member_matches(
    primary: &ResolvedMemberDiscovery,
    candidate: &ResolvedMemberDiscovery,
    discovered_ids: &[FilesystemMemberId],
) -> bool {
    let candidate_id = candidate.discovery().member();
    primary.driver_name() == candidate.driver_name()
        && primary.discovery().detected() == candidate.discovery().detected()
        && primary.discovery().requires(candidate_id)
        && !discovered_ids.contains(candidate_id)
}

fn discovery_complete(
    primary: &ResolvedMemberDiscovery,
    discovered_ids: &[FilesystemMemberId],
) -> bool {
    primary
        .discovery()
        .required_members()
        .iter()
        .all(|required| discovered_ids.contains(required))
}

fn discover_raw_partitions<E: HostVolumeResolver>(
    primary_drive: &HostDriveId,
    primary: &ResolvedMemberDiscovery,
    discovered_ids: &mut Vec<FilesystemMemberId>,
    devices: &mut DeviceSet,
    extents: &mut Vec<PhysicalExtent>,
    drivers: &DriverRegistry,
    policy: &ReadPolicy,
) {
    if discovery_complete(primary, discovered_ids) {
        return;
    }

    let mut host_ids = vec![primary_drive.clone()];
    if let Ok(host_drives) = E::enumerate_drives() {
        for info in host_drives {
            if !host_ids.contains(&info.id) {
                host_ids.push(info.id);
            }
        }
    }

    for drive in host_ids {
        // Every other drive is read in its own reported geometry: an
        // override chosen for the drive the caller named says nothing about
        // the ones a filesystem happens to reference.
        let Ok(partitions) = locate_partitions::<E>(&drive, None) else {
            continue;
        };
        for located in partitions {
            if extents.contains(&located.extent) {
                continue;
            }
            let Ok(mut member) = open_raw_member::<E>(&located, policy) else {
                continue;
            };
            let Ok(Some(candidate)) = discover_member(drivers, &mut member) else {
                continue;
            };
            if !member_matches(primary, &candidate, discovered_ids) {
                continue;
            }
            if devices.push(member).is_err() {
                continue;
            }
            debug!(
                drive = %located.extent.drive(),
                offset = located.extent.offset(),
                member = ?candidate.discovery().member(),
                "adopted another partition as a member of the same filesystem"
            );
            discovered_ids.push(candidate.discovery().member().clone());
            extents.push(located.extent);
            if discovery_complete(primary, discovered_ids) {
                return;
            }
        }
    }
}

fn open_raw_member<E: HostVolumeResolver>(
    located: &LocatedPartition,
    policy: &ReadPolicy,
) -> Result<DeviceMember, Box<dyn std::error::Error>> {
    let reader = E::open_drive(located.extent.drive())?;
    let zone_reporter = E::physical_zone_reporter(&located.extent)?;
    let length = whole_sectors(located.extent.length(), located.sector_size);
    let partition = PartitionReader::new(reader, located.extent.offset(), length);
    let reader = SectorReader::new(partition, length, located.sector_size)?;
    let mut member = DeviceMember::new(
        SourceMemberId::Physical(located.extent.clone()),
        policy.wrap(reader, length)?,
        length,
        located.sector_size,
    )?;
    if let Some(zone_reporter) = zone_reporter {
        member = member.with_zone_reporter(zone_reporter);
    }
    Ok(member)
}

fn open_devices(
    mut devices: DeviceSet,
    source: SourceOrigin,
    size: u64,
    layout_origin: Option<LayoutOrigin>,
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
    policy: &ReadPolicy,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    // Bounded to the member so a dead sector 0 can still be classified from
    // the format's backup copies (see `detect_boot_sector_within`).
    let length = devices.primary_mut().length();
    let detected =
        fsmnt_device::detect_boot_sector_within(devices.primary_mut().reader_mut(), 0, length)?;
    std::io::Seek::seek(
        devices.primary_mut().reader_mut(),
        std::io::SeekFrom::Start(0),
    )?;
    let detected = ext_backup::detection_with_backup_request(detected, filesystem);
    let opened = drivers.open_devices_with_options_resolved(devices, detected, filesystem)?;

    let size_bytes = if size == u64::MAX { 0 } else { size };
    // A partition whose size is unknown (0) cannot contradict anything the
    // filesystem claims, so it never reports a shortfall.
    let truncated_by = (size_bytes > 0)
        .then(|| truncation::missing_filesystem_bytes(opened.filesystem.total_size(), size_bytes))
        .flatten();
    Ok(OpenedPartition {
        filesystem: opened.filesystem,
        detected: opened.detected,
        size_bytes,
        truncated_by,
        source,
        substitutions: policy.substitutions.clone(),
        layout_origin,
    })
}
