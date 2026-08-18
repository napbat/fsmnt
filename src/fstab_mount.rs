//! fstab namespace assembly, over whichever medium carries the volumes.
//!
//! A Linux root filesystem describes the rest of its tree in `/etc/fstab`,
//! by UUID rather than by device path, because the path a volume had when
//! the system last ran is not the path it has anywhere else. Composing that
//! tree therefore means finding the volumes: opening every sibling the
//! medium offers, asking each for its UUID, and attaching the ones fstab
//! names.
//!
//! The search is the only part that differs between a live drive and a disk
//! image, so it is the only part that is abstracted ([`FstabSiblings`]);
//! [`compose_fstab_namespace`] holds the rest — root validation, mount
//! ordering, `noauto`/`nofail` handling — once, for both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tracing::debug;

use fsmnt_core::{Fstab, FstabEntry, FstabSource, MountNamespace, TargetFilesystem};
use fsmnt_device::{
    DriverRegistry, FilesystemOpenOptions, FilesystemRoot, HostDriveId, HostVolumeResolver,
    PartitionAddress, SourceSelection,
};

use crate::open_device::locate_partitions;
use crate::{
    ImageLayoutOptions, ImageOpenOptions, OpenedImage, OpenedPartition, PartitionOpenOptions,
    image_layout_with_options, open_device_partition_with_options, open_image_with_options,
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
    let selection = options.source().clone();
    let sector_size = options.sector_size();
    let root = open_device_partition_with_options::<E>(drive, partition, drivers, options)?;
    let mut siblings = DeviceSiblings::<E> {
        root: PartitionAddress::new(drive.clone(), partition),
        drivers,
        selection,
        sector_size,
        enumerator: std::marker::PhantomData,
    };
    let filesystem = root.filesystem;
    let namespace = compose_fstab_namespace(filesystem, fstab_path, &mut siblings)?;
    Ok(OpenedPartition {
        filesystem: Box::new(namespace),
        ..root
    })
}

/// Open a filesystem inside a disk image and compose the child filesystems
/// its fstab declares from the other partitions of the same image.
///
/// The root is located exactly as [`open_image_with_options`] would: by the
/// partition ordinal or byte offset in `options`, at the requested sector
/// size, against a scanned synthetic table when one was asked for. Children
/// come from the remaining partitions of the same layout, so a VM disk holds
/// everything needed to reassemble the guest's tree — which is the usual
/// reason to point fstab composition at an image.
///
/// Children inherit the container-level choices that decide *what the bytes
/// are* — sector size, scan stride, best-effort reads — but not the root's
/// own filesystem choices (`--fs-root`, salvage, a backup superblock):
/// those answer a question asked about the root volume, and the only
/// filesystem-level selector a child gets is the `subvol`/`subvolid` its
/// fstab entry names.
///
/// Virtual filesystems and entries marked `noauto` are ignored. An
/// unresolved `nofail` entry is skipped; other unresolved or unsupported
/// sources are errors.
///
/// # Errors
///
/// Returns an error if the image or its root filesystem cannot be opened,
/// fstab cannot be read or parsed, the root entry's UUID contradicts the
/// filesystem actually opened, a required source cannot be resolved, a child
/// filesystem cannot be opened, or its mount point is invalid.
pub fn open_image_with_fstab(
    path: impl AsRef<Path>,
    drivers: &DriverRegistry,
    options: ImageOpenOptions,
    fstab_path: &str,
) -> Result<OpenedImage, Box<dyn std::error::Error>> {
    let path = path.as_ref();
    let root = open_image_with_options(path, drivers, options.clone())?;
    let mut siblings = ImageSiblings {
        path: path.to_path_buf(),
        drivers,
        root: ImageAddress {
            offset: root.offset,
            partition: options.partition(),
        },
        options,
    };
    let filesystem = root.filesystem;
    let namespace = compose_fstab_namespace(filesystem, fstab_path, &mut siblings)?;
    Ok(OpenedImage {
        filesystem: Box::new(namespace),
        ..root
    })
}

/// The volumes an fstab composition may draw its child filesystems from.
///
/// One implementation per kind of medium: the partitions of every host drive
/// for a device, the partitions of one image for an image. Addresses are
/// compared, never interpreted, by [`compose_fstab_namespace`].
trait FstabSiblings {
    /// How this medium names one candidate volume.
    type Address: Clone + PartialEq + std::fmt::Debug;

    /// The address of the root filesystem that is already open.
    fn root(&self) -> Self::Address;

    /// Every volume that could hold a child filesystem, in search order.
    ///
    /// The root is included — implementations need not filter it out;
    /// composition skips any candidate equal to [`root`](Self::root),
    /// because the root's UUID comes from the filesystem already open
    /// rather than from opening it a second time.
    fn candidates(&mut self) -> Result<Vec<Self::Address>, Box<dyn std::error::Error>>;

    /// Open the filesystem at `address`, exposing `root` of it.
    ///
    /// Called both to read a candidate's UUID (with
    /// [`FilesystemRoot::Default`]) and to open the child an fstab entry
    /// resolved to (with the `subvol`/`subvolid` that entry names).
    fn open(
        &mut self,
        address: &Self::Address,
        root: FilesystemRoot,
    ) -> Result<Box<dyn TargetFilesystem>, Box<dyn std::error::Error>>;
}

/// Read `fstab_path` through `root_fs` and assemble the namespace it
/// describes, drawing child filesystems from `siblings`.
///
/// Child mounts are attached shallow-to-deep so a nested mount point such as
/// `/boot/efi` is attached after the `/boot` it lives in.
fn compose_fstab_namespace(
    mut root_fs: Box<dyn TargetFilesystem>,
    fstab_path: &str,
    siblings: &mut impl FstabSiblings,
) -> Result<MountNamespace, Box<dyn std::error::Error>> {
    let contents = root_fs.read_to_string(fstab_path)?;
    let fstab: Fstab = contents.parse()?;
    validate_root_entry(&fstab, root_fs.as_ref())?;

    let entries = mount_entries(&fstab);
    let requested_uuids: BTreeSet<String> = entries
        .iter()
        .filter_map(|entry| source_uuid(entry.source()))
        .map(normalize_uuid)
        .collect();
    let resolved = discover_uuid_addresses(root_fs.as_ref(), &requested_uuids, siblings)?;
    debug!(
        path = fstab_path,
        entries = entries.len(),
        requested = requested_uuids.len(),
        resolved = resolved.len(),
        "read the guest's fstab and located the volumes it names"
    );

    let mut namespace = MountNamespace::new(root_fs);
    for entry in entries {
        if entry.has_option("noauto") || is_virtual_filesystem(entry) {
            debug!(
                mount_point = entry.mount_point(),
                filesystem_type = entry.filesystem_type(),
                "skipped an fstab entry: noauto, or a filesystem the kernel makes up"
            );
            continue;
        }
        let result = open_fstab_entry(entry, siblings, &resolved).and_then(|child| {
            namespace
                .attach(entry.mount_point(), child)
                .map_err(Into::into)
        });
        if let Err(error) = result {
            if entry.has_option("nofail") {
                debug!(
                    mount_point = entry.mount_point(),
                    error = %error,
                    "skipped an fstab entry marked nofail that could not be attached"
                );
                continue;
            }
            return Err(format!(
                "failed to attach fstab mount {}: {error}",
                entry.mount_point()
            )
            .into());
        }
        debug!(
            mount_point = entry.mount_point(),
            source = ?entry.source(),
            "attached an fstab child mount"
        );
    }
    Ok(namespace)
}

/// The child mounts of an fstab, ordered shallow-to-deep.
///
/// The `/` entry is not a child mount: it describes the filesystem already
/// open, which [`validate_root_entry`] checks rather than attaches.
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

/// Refuse a composition whose fstab describes a different root volume.
///
/// An fstab is only a map of the tree it belongs to. Assembling one on top
/// of the wrong volume would silently produce a plausible-looking namespace
/// made of other machines' filesystems, so a `/` entry naming a UUID must
/// name this one.
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

/// Map each UUID the fstab asks for to the volume that carries it.
///
/// The root answers for itself; the remaining candidates are opened one at a
/// time only until every requested UUID is accounted for, and a candidate
/// that fails to open is simply not the volume being looked for. The first
/// candidate carrying a UUID wins, so search order decides ties.
fn discover_uuid_addresses<S: FstabSiblings>(
    root_filesystem: &dyn TargetFilesystem,
    requested: &BTreeSet<String>,
    siblings: &mut S,
) -> Result<BTreeMap<String, S::Address>, Box<dyn std::error::Error>> {
    let root = siblings.root();
    let mut resolved = BTreeMap::new();
    if let Some(uuid) = root_filesystem.volume_uuid() {
        let uuid = normalize_uuid(&uuid);
        if requested.contains(&uuid) {
            resolved.insert(uuid, root.clone());
        }
    }
    let all_found = |resolved: &BTreeMap<String, S::Address>| {
        requested.iter().all(|uuid| resolved.contains_key(uuid))
    };
    if all_found(&resolved) {
        return Ok(resolved);
    }

    for address in siblings.candidates()? {
        if address == root {
            continue;
        }
        let Ok(candidate) = siblings.open(&address, FilesystemRoot::Default) else {
            continue;
        };
        let Some(uuid) = candidate.volume_uuid() else {
            continue;
        };
        let uuid = normalize_uuid(&uuid);
        if requested.contains(&uuid) {
            resolved.entry(uuid).or_insert(address);
        }
        if all_found(&resolved) {
            break;
        }
    }
    Ok(resolved)
}

/// Open the filesystem one fstab entry mounts, with the subvolume it names.
fn open_fstab_entry<S: FstabSiblings>(
    entry: &FstabEntry,
    siblings: &mut S,
    resolved: &BTreeMap<String, S::Address>,
) -> Result<Box<dyn TargetFilesystem>, Box<dyn std::error::Error>> {
    let uuid = source_uuid(entry.source()).ok_or_else(|| {
        format!(
            "source {:?} is not yet resolvable on this host",
            entry.source()
        )
    })?;
    let address = resolved
        .get(&normalize_uuid(uuid))
        .ok_or_else(|| format!("filesystem UUID {uuid:?} was not found"))?
        .clone();
    let root = filesystem_root(entry)?;
    siblings.open(&address, root)
}

/// Partitions of the host drives, searched root drive first.
struct DeviceSiblings<'drivers, E: HostVolumeResolver> {
    /// The partition the root filesystem was opened from.
    root: PartitionAddress,
    /// Drivers used to open each candidate.
    drivers: &'drivers DriverRegistry,
    /// The root's block-source selection, from which each sibling's is
    /// derived (see [`sibling_source_selection`]).
    selection: SourceSelection,
    /// The sector size the root drive's table was read in, when the caller
    /// stated one. It describes that drive, so siblings on it are located
    /// with it; other drives report their own geometry.
    sector_size: Option<u32>,
    /// The platform enumerator every open goes through.
    enumerator: std::marker::PhantomData<E>,
}

impl<E: HostVolumeResolver> FstabSiblings for DeviceSiblings<'_, E> {
    type Address = PartitionAddress;

    fn root(&self) -> Self::Address {
        self.root.clone()
    }

    fn candidates(&mut self) -> Result<Vec<Self::Address>, Box<dyn std::error::Error>> {
        // The root drive is searched first: a machine's fstab overwhelmingly
        // names volumes on the drive its root lives on, so the other drives
        // are usually never touched.
        let mut drives = vec![self.root.drive().clone()];
        for info in E::enumerate_drives()? {
            if info.id != *self.root.drive() {
                drives.push(info.id);
            }
        }
        let mut addresses = vec![self.root.clone()];
        for drive in drives {
            let Ok(partitions) = locate_partitions::<E>(&drive, self.sector_size_for(&drive))
            else {
                continue;
            };
            for partition in 0..partitions.len() {
                addresses.push(PartitionAddress::new(drive.clone(), partition));
            }
        }
        Ok(addresses)
    }

    fn open(
        &mut self,
        address: &Self::Address,
        root: FilesystemRoot,
    ) -> Result<Box<dyn TargetFilesystem>, Box<dyn std::error::Error>> {
        let source = if *address == self.root {
            self.selection.clone()
        } else {
            sibling_source_selection(&self.selection)
        };
        let mut options = PartitionOpenOptions::new()
            .with_source(source)
            .with_filesystem_root(root);
        if let Some(sector_size) = self.sector_size_for(address.drive()) {
            options = options.with_sector_size(sector_size);
        }
        Ok(open_device_partition_with_options::<E>(
            address.drive(),
            address.partition(),
            self.drivers,
            options,
        )?
        .filesystem)
    }
}

impl<E: HostVolumeResolver> DeviceSiblings<'_, E> {
    /// The sector size to read `drive`'s table in: the caller's, for the
    /// root drive; the drive's own report otherwise.
    fn sector_size_for(&self, drive: &HostDriveId) -> Option<u32> {
        (drive == self.root.drive())
            .then_some(self.sector_size)
            .flatten()
    }
}

/// Where a filesystem sits inside a disk image.
///
/// The byte offset is the identity — the root may have been addressed by
/// offset rather than by ordinal, and it is still the same volume as the
/// layout entry starting there — while the ordinal is how the image is
/// reopened.
#[derive(Clone, Debug)]
struct ImageAddress {
    /// Byte offset of the volume within the decoded media.
    offset: u64,
    /// Ordinal to reopen it by, or `None` for a root addressed by offset.
    partition: Option<usize>,
}

impl PartialEq for ImageAddress {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset
    }
}

/// The other partitions of the same disk image.
struct ImageSiblings<'drivers> {
    /// Path the image was opened from; each sibling reopens it.
    path: PathBuf,
    /// Drivers used to open each candidate.
    drivers: &'drivers DriverRegistry,
    /// Where the root filesystem was opened.
    root: ImageAddress,
    /// The root's open options, whose container-level choices (sector size,
    /// scan stride, best-effort reads) describe the medium and so apply to
    /// every volume on it.
    options: ImageOpenOptions,
}

impl FstabSiblings for ImageSiblings<'_> {
    type Address = ImageAddress;

    fn root(&self) -> Self::Address {
        self.root.clone()
    }

    fn candidates(&mut self) -> Result<Vec<Self::Address>, Box<dyn std::error::Error>> {
        // Enumerated the way the root was located, or the ordinals would
        // mean something else: a scanned synthetic table numbers the
        // filesystems a scan found, and a 4Kn table read in 512-byte
        // sectors puts every partition in the wrong place.
        let mut layout_options = ImageLayoutOptions::new();
        if let Some(sector_size) = self.options.sector_size() {
            layout_options = layout_options.with_sector_size(sector_size);
        }
        if let Some(stride) = self.options.scan_stride() {
            layout_options = layout_options.with_scan(true).with_scan_stride(stride);
        }
        let layout = image_layout_with_options(&self.path, layout_options)?;
        Ok(layout
            .partitions
            .iter()
            .map(|partition| ImageAddress {
                offset: partition.offset,
                partition: Some(partition.ordinal),
            })
            .collect())
    }

    fn open(
        &mut self,
        address: &Self::Address,
        root: FilesystemRoot,
    ) -> Result<Box<dyn TargetFilesystem>, Box<dyn std::error::Error>> {
        let located = self.options.clone();
        // An ordinal supersedes the offset the options carry; without one
        // this is the root's own extent, which those options already name.
        let located = match address.partition {
            Some(partition) => located.with_partition(partition),
            None => located,
        };
        Ok(open_image_with_options(
            &self.path,
            self.drivers,
            located.with_filesystem_options(FilesystemOpenOptions::new().with_root(root)),
        )?
        .filesystem)
    }
}

/// Translate an fstab entry's subvolume options into a root selector.
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

/// The source selection a sibling volume is opened with.
///
/// Raw stays raw — a caller reading a device raw wants every volume read raw
/// — but the root's multi-device members belong to the root's filesystem and
/// say nothing about a sibling's, and a logical volume chosen for the root
/// is by definition not the sibling's.
fn sibling_source_selection(selection: &SourceSelection) -> SourceSelection {
    match selection {
        SourceSelection::Raw { .. } => SourceSelection::Raw {
            additional_partitions: Vec::new(),
        },
        SourceSelection::Auto | SourceSelection::Logical(_) => SourceSelection::Auto,
    }
}

/// The UUID an fstab source names, if it names one at all.
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

/// UUIDs are compared case-insensitively; this is the comparable form.
fn normalize_uuid(uuid: &str) -> String {
    uuid.to_ascii_lowercase()
}

/// Whether an entry mounts something the kernel makes up rather than a
/// volume that exists on any medium.
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

    #[test]
    fn an_image_volume_is_identified_by_its_offset_not_its_ordinal() {
        let by_offset = ImageAddress {
            offset: 8192,
            partition: None,
        };
        let by_ordinal = ImageAddress {
            offset: 8192,
            partition: Some(1),
        };
        assert_eq!(
            by_offset, by_ordinal,
            "a root opened at an offset is the layout entry starting there"
        );
        assert_ne!(
            by_ordinal,
            ImageAddress {
                offset: 4096,
                partition: Some(1),
            }
        );
    }
}
