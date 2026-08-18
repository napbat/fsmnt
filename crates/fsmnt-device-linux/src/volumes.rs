//! Linux logical-volume discovery through the sysfs block graph.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use fsmnt_device::{
    BlockZoneReporter, HostDriveId, HostDriveResult, HostVolumeResolver, LogicalVolume,
    LogicalVolumeId, PhysicalExtent,
};
use tracing::debug;

use crate::drives::{LinuxHostDrives, open_device};
use crate::zones::reporter_for_path;

const SYSFS_SECTOR_SIZE: u64 = 512;

impl HostVolumeResolver for LinuxHostDrives {
    type VolumeReader = std::fs::File;

    fn logical_volumes(extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        let Some(partition) = find_partition_for_extent(extent)? else {
            return Ok(Vec::new());
        };

        let mut leaves = Vec::new();
        collect_holder_leaves(&partition, &mut HashSet::new(), &mut leaves);
        leaves.sort();
        leaves.dedup();

        let volumes: Vec<LogicalVolume> = leaves
            .into_iter()
            .map(|name| logical_volume(&name, extent))
            .collect();

        debug!(
            drive = %extent.drive(),
            offset = extent.offset(),
            partition = %partition,
            count = volumes.len(),
            "logical-volume candidates for extent"
        );
        for volume in &volumes {
            debug!(
                volume = %volume.id(),
                mount_points = ?volume.mount_points(),
                "logical-volume candidate"
            );
        }

        Ok(volumes)
    }

    fn physical_zone_reporter(
        extent: &PhysicalExtent,
    ) -> HostDriveResult<Option<Box<dyn BlockZoneReporter>>> {
        reporter_for_path(
            &format!("/dev/{}", extent.drive()),
            extent.offset(),
            extent.length(),
        )
    }

    fn open_logical_volume(volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        open_device(&volume.device_path().to_string_lossy())
    }

    fn logical_zone_reporter(
        volume: &LogicalVolume,
    ) -> HostDriveResult<Option<Box<dyn BlockZoneReporter>>> {
        reporter_for_path(
            &volume.device_path().to_string_lossy(),
            0,
            volume.length().unwrap_or(u64::MAX),
        )
    }
}

fn find_partition_for_extent(extent: &PhysicalExtent) -> HostDriveResult<Option<String>> {
    let whole_device = PathBuf::from("/sys/class/block").join(extent.drive().as_str());
    if block_extent(&whole_device)
        .as_ref()
        .is_some_and(|candidate| {
            candidate.has_same_start(extent)
                && (extent.length() == u64::MAX || candidate.length() == extent.length())
        })
    {
        return Ok(Some(extent.drive().as_str().to_string()));
    }

    for entry in fs::read_dir("/sys/class/block")?.flatten() {
        let path = entry.path();
        if !path.join("partition").exists() {
            continue;
        }
        if block_extent(&path)
            .as_ref()
            .is_some_and(|candidate| candidate.has_same_start(extent))
        {
            return Ok(Some(entry.file_name().to_string_lossy().into_owned()));
        }
    }
    Ok(None)
}

fn collect_holder_leaves(name: &str, visited: &mut HashSet<String>, leaves: &mut Vec<String>) {
    if !visited.insert(name.to_string()) {
        return;
    }

    let holders_path = PathBuf::from("/sys/class/block").join(name).join("holders");
    let holders: Vec<String> = fs::read_dir(holders_path)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();

    if holders.is_empty() {
        leaves.push(name.to_string());
    } else {
        for holder in holders {
            collect_holder_leaves(&holder, visited, leaves);
        }
    }
}

fn logical_volume(name: &str, seed: &PhysicalExtent) -> LogicalVolume {
    let mut backing_extents = Vec::new();
    collect_backing_extents(name, &mut HashSet::new(), &mut backing_extents);
    if backing_extents.is_empty() {
        backing_extents.push(seed.clone());
    }
    backing_extents.sort_by(|left, right| {
        left.drive()
            .as_str()
            .cmp(right.drive().as_str())
            .then_with(|| left.offset().cmp(&right.offset()))
            .then_with(|| left.length().cmp(&right.length()))
    });
    backing_extents.dedup();

    let sysfs_path = PathBuf::from("/sys/class/block").join(name);
    let id = read_trimmed(&sysfs_path.join("dm/uuid"))
        .filter(|uuid| !uuid.is_empty())
        .map_or_else(|| name.to_string(), |uuid| format!("dm:{uuid}"));
    let mount_points = mount_points_for(name);

    let mut volume = LogicalVolume::new(
        LogicalVolumeId::new(id),
        PathBuf::from("/dev").join(name),
        backing_extents,
    )
    .with_mount_points(mount_points);
    if let Some(length) = block_length(&sysfs_path) {
        volume = volume.with_length(length);
    }
    if let Some(sector_size) = block_sector_size(&sysfs_path) {
        volume = volume.with_sector_size(sector_size);
    }
    volume
}

fn collect_backing_extents(
    name: &str,
    visited: &mut HashSet<String>,
    extents: &mut Vec<PhysicalExtent>,
) {
    if !visited.insert(name.to_string()) {
        return;
    }
    let path = PathBuf::from("/sys/class/block").join(name);
    let slaves_path = path.join("slaves");
    if let Ok(slaves) = fs::read_dir(slaves_path) {
        let mut found_slave = false;
        for slave in slaves.flatten() {
            found_slave = true;
            collect_backing_extents(&slave.file_name().to_string_lossy(), visited, extents);
        }
        if found_slave {
            return;
        }
    }

    if let Some(extent) = block_extent(&path) {
        extents.push(extent);
    }
}

fn block_extent(sysfs_path: &Path) -> Option<PhysicalExtent> {
    let length = block_length(sysfs_path)?;
    if sysfs_path.join("partition").exists() {
        let start_sectors: u64 = read_trimmed(&sysfs_path.join("start"))?.parse().ok()?;
        let offset = start_sectors.checked_mul(SYSFS_SECTOR_SIZE)?;
        let canonical = fs::canonicalize(sysfs_path).ok()?;
        let drive = canonical.parent()?.file_name()?.to_string_lossy();
        return Some(PhysicalExtent::new(
            HostDriveId::new(drive.into_owned()),
            offset,
            length,
        ));
    }

    let name = sysfs_path.file_name()?.to_string_lossy();
    PathBuf::from("/sys/block")
        .join(name.as_ref())
        .exists()
        .then(|| PhysicalExtent::new(HostDriveId::new(name.into_owned()), 0, length))
}

fn mount_points_for(name: &str) -> Vec<PathBuf> {
    let sysfs_path = PathBuf::from("/sys/class/block").join(name);
    let Some(device_number) = read_trimmed(&sysfs_path.join("dev")) else {
        return Vec::new();
    };
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };

    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.get(2).copied() == Some(device_number.as_str()))
                .then(|| {
                    fields
                        .get(4)
                        .map(|path| PathBuf::from(unescape_mount_path(path)))
                })
                .flatten()
        })
        .collect()
}

fn unescape_mount_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn block_length(sysfs_path: &Path) -> Option<u64> {
    let sectors: u64 = read_trimmed(&sysfs_path.join("size"))?.parse().ok()?;
    sectors.checked_mul(SYSFS_SECTOR_SIZE)
}

fn block_sector_size(sysfs_path: &Path) -> Option<u32> {
    read_trimmed(&sysfs_path.join("queue/logical_block_size"))?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::unescape_mount_path;

    #[test]
    fn mountinfo_path_escapes_are_decoded() {
        assert_eq!(
            unescape_mount_path("/media/My\\040Disk\\134Folder"),
            "/media/My Disk\\Folder"
        );
    }
}
