//! Device-backed fstab namespace assembly.

use std::collections::{BTreeMap, BTreeSet};

use fsmnt_core::{Fstab, FstabEntry, FstabSource, MountNamespace, TargetFilesystem};
use fsmnt_device::{
    DriverRegistry, FilesystemRoot, HostDriveId, HostVolumeResolver, PartitionAddress,
    SourceSelection,
};

use crate::{
    OpenedPartition, PartitionOpenOptions, locate_partitions, open_device_partition_with_options,
};

/// Open a device partition and compose child filesystems declared by fstab.
///
/// `fstab_path` is read through the already-selected root filesystem. Sources
/// identified by `UUID=` are resolved across host drives, then opened using the
/// same raw-vs-logical policy as the root. Child mounts are attached in
/// shallow-to-deep order so nested mount points such as `/boot/efi` work.
///
/// Virtual filesystems and entries marked `noauto` are ignored. An unresolved
/// `nofail` entry is skipped; other unresolved or unsupported sources are
/// errors.
///
/// # Errors
///
/// Returns an error if the root cannot be opened, fstab cannot be read or
/// parsed, a required source cannot be resolved, a child filesystem cannot be
/// opened, or its mount point is invalid.
pub fn open_device_partition_with_fstab<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
    fstab_path: &str,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let source_selection = options.source().clone();
    let root = open_device_partition_with_options::<E>(drive, partition, drivers, options)?;
    let OpenedPartition {
        mut filesystem,
        detected,
        size_bytes,
        truncated_by,
        source,
    } = root;
    let contents = filesystem.read_to_string(fstab_path)?;
    let fstab: Fstab = contents.parse()?;
    validate_root_entry(&fstab, filesystem.as_ref())?;

    let entries = mount_entries(&fstab);
    let requested_uuids: BTreeSet<String> = entries
        .iter()
        .filter_map(|entry| source_uuid(entry.source()))
        .map(normalize_uuid)
        .collect();
    let resolved = discover_uuid_partitions::<E>(
        drive,
        partition,
        filesystem.as_ref(),
        &requested_uuids,
        drivers,
        &source_selection,
    )?;

    let mut namespace = MountNamespace::new(filesystem);
    for entry in entries {
        if entry.has_option("noauto") || is_virtual_filesystem(entry) {
            continue;
        }
        let result = open_fstab_entry::<E>(
            entry,
            drive,
            partition,
            drivers,
            &source_selection,
            &resolved,
        )
        .and_then(|child| {
            namespace
                .attach(entry.mount_point(), child)
                .map_err(Into::into)
        });
        if let Err(error) = result {
            if entry.has_option("nofail") {
                continue;
            }
            return Err(format!(
                "failed to attach fstab mount {}: {error}",
                entry.mount_point()
            )
            .into());
        }
    }

    Ok(OpenedPartition {
        filesystem: Box::new(namespace),
        detected,
        size_bytes,
        truncated_by,
        source,
    })
}

fn mount_entries(fstab: &Fstab) -> Vec<&FstabEntry> {
    let mut entries: Vec<&FstabEntry> = fstab
        .entries()
        .iter()
        .filter(|entry| entry.mount_point() != "/")
        .collect();
    entries.sort_by_key(|entry| {
        entry
            .mount_point()
            .split('/')
            .filter(|component| !component.is_empty())
            .count()
    });
    entries
}

fn validate_root_entry(
    fstab: &Fstab,
    filesystem: &dyn TargetFilesystem,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = fstab
        .entries()
        .iter()
        .find(|entry| entry.mount_point() == "/")
    else {
        return Ok(());
    };
    let Some(expected) = source_uuid(root.source()) else {
        return Ok(());
    };
    let actual = filesystem
        .volume_uuid()
        .ok_or("the selected root filesystem does not expose a UUID")?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "fstab root UUID {expected:?} does not match opened filesystem UUID {actual:?}"
        )
        .into());
    }
    Ok(())
}

fn discover_uuid_partitions<E: HostVolumeResolver>(
    root_drive: &HostDriveId,
    root_partition: usize,
    root_filesystem: &dyn TargetFilesystem,
    requested: &BTreeSet<String>,
    drivers: &DriverRegistry,
    selection: &SourceSelection,
) -> Result<BTreeMap<String, PartitionAddress>, Box<dyn std::error::Error>> {
    let mut resolved = BTreeMap::new();
    if let Some(uuid) = root_filesystem.volume_uuid() {
        let uuid = normalize_uuid(&uuid);
        if requested.contains(&uuid) {
            resolved.insert(
                uuid,
                PartitionAddress::new(root_drive.clone(), root_partition),
            );
        }
    }
    if requested.iter().all(|uuid| resolved.contains_key(uuid)) {
        return Ok(resolved);
    }

    let mut host_drives = vec![root_drive.clone()];
    for info in E::enumerate_drives()? {
        if info.id != *root_drive {
            host_drives.push(info.id);
        }
    }
    for drive in host_drives {
        let Ok(partitions) = locate_partitions::<E>(&drive) else {
            continue;
        };
        for partition in 0..partitions.len() {
            if drive == *root_drive && partition == root_partition {
                continue;
            }
            let child_selection = sibling_source_selection(selection);
            let candidate = open_device_partition_with_options::<E>(
                &drive,
                partition,
                drivers,
                PartitionOpenOptions::new().with_source(child_selection),
            );
            let Ok(candidate) = candidate else {
                continue;
            };
            let Some(uuid) = candidate.filesystem.volume_uuid() else {
                continue;
            };
            let uuid = normalize_uuid(&uuid);
            if requested.contains(&uuid) {
                resolved
                    .entry(uuid)
                    .or_insert_with(|| PartitionAddress::new(drive.clone(), partition));
            }
        }
        if requested.iter().all(|uuid| resolved.contains_key(uuid)) {
            break;
        }
    }
    Ok(resolved)
}

fn open_fstab_entry<E: HostVolumeResolver>(
    entry: &FstabEntry,
    root_drive: &HostDriveId,
    root_partition: usize,
    drivers: &DriverRegistry,
    selection: &SourceSelection,
    resolved: &BTreeMap<String, PartitionAddress>,
) -> Result<Box<dyn TargetFilesystem>, Box<dyn std::error::Error>> {
    let uuid = source_uuid(entry.source()).ok_or_else(|| {
        format!(
            "source {:?} is not yet resolvable on this host",
            entry.source()
        )
    })?;
    let address = resolved
        .get(&normalize_uuid(uuid))
        .ok_or_else(|| format!("filesystem UUID {uuid:?} was not found"))?;
    let is_root_partition = address.drive() == root_drive && address.partition() == root_partition;
    let source = if is_root_partition {
        selection.clone()
    } else {
        sibling_source_selection(selection)
    };
    let root = filesystem_root(entry)?;
    Ok(open_device_partition_with_options::<E>(
        address.drive(),
        address.partition(),
        drivers,
        PartitionOpenOptions::new()
            .with_source(source)
            .with_filesystem_root(root),
    )?
    .filesystem)
}

fn filesystem_root(entry: &FstabEntry) -> Result<FilesystemRoot, Box<dyn std::error::Error>> {
    if let Some(path) = entry.option("subvol") {
        return Ok(FilesystemRoot::Path(
            path.trim_start_matches('/').to_string(),
        ));
    }
    if let Some(id) = entry.option("subvolid") {
        return Ok(FilesystemRoot::Id(id.parse()?));
    }
    Ok(FilesystemRoot::Default)
}

fn sibling_source_selection(selection: &SourceSelection) -> SourceSelection {
    match selection {
        SourceSelection::Raw { .. } => SourceSelection::Raw {
            additional_partitions: Vec::new(),
        },
        SourceSelection::Auto | SourceSelection::Logical(_) => SourceSelection::Auto,
    }
}

fn source_uuid(source: &FstabSource) -> Option<&str> {
    match source {
        FstabSource::Uuid(uuid) => Some(uuid),
        FstabSource::Device(path) => path.strip_prefix("/dev/disk/by-uuid/"),
        FstabSource::Label(_)
        | FstabSource::PartitionUuid(_)
        | FstabSource::PartitionLabel(_)
        | FstabSource::None => None,
    }
}

fn normalize_uuid(uuid: &str) -> String {
    uuid.to_ascii_lowercase()
}

fn is_virtual_filesystem(entry: &FstabEntry) -> bool {
    matches!(entry.source(), FstabSource::None)
        || matches!(
            entry.filesystem_type(),
            "proc"
                | "sysfs"
                | "devtmpfs"
                | "devpts"
                | "tmpfs"
                | "swap"
                | "cgroup"
                | "cgroup2"
                | "debugfs"
                | "securityfs"
                | "pstore"
                | "efivarfs"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_subvolume_options_to_generic_root_selectors() {
        let fstab: Fstab = concat!(
            "UUID=x /home btrfs subvol=/home 0 0\n",
            "UUID=x /snap btrfs subvolid=257 0 0\n",
            "UUID=y /boot ext4 defaults 0 2\n",
        )
        .parse()
        .expect("fstab");
        assert_eq!(
            filesystem_root(&fstab.entries()[0]).expect("path root"),
            FilesystemRoot::Path("home".to_string())
        );
        assert_eq!(
            filesystem_root(&fstab.entries()[1]).expect("ID root"),
            FilesystemRoot::Id(257)
        );
        assert_eq!(
            filesystem_root(&fstab.entries()[2]).expect("default root"),
            FilesystemRoot::Default
        );
    }

    #[test]
    fn child_mounts_are_ordered_before_nested_descendants() {
        let fstab: Fstab = concat!(
            "UUID=a /boot/efi vfat defaults 0 2\n",
            "UUID=b /home btrfs subvol=home 0 0\n",
            "UUID=c /boot ext4 defaults 0 2\n",
        )
        .parse()
        .expect("fstab");
        let points: Vec<&str> = mount_entries(&fstab)
            .into_iter()
            .map(FstabEntry::mount_point)
            .collect();
        assert_eq!(points, ["/home", "/boot", "/boot/efi"]);
    }

    #[test]
    fn raw_policy_is_inherited_without_unrelated_multi_device_members() {
        let selection = SourceSelection::Raw {
            additional_partitions: vec![PartitionAddress::new(HostDriveId::new("other"), 3)],
        };
        assert_eq!(
            sibling_source_selection(&selection),
            SourceSelection::Raw {
                additional_partitions: Vec::new()
            }
        );
        assert_eq!(
            sibling_source_selection(&SourceSelection::Logical(
                fsmnt_device::LogicalVolumeId::new("volume")
            )),
            SourceSelection::Auto
        );
    }
}
