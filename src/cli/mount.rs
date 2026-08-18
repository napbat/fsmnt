//! The mounting subcommands: host directories, disk images, and devices.

use super::{block_on_mount, build_registry, ensure_unix_mountpoint, fs_label};

use fsmnt::DirFilesystem;

/// Mount `source` at `mountpoint` and block until Ctrl+C.
pub(crate) fn handle_mount(
    source: &std::path::Path,
    mountpoint: &str,
    volname: &str,
    fsname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !source.is_dir() {
        return Err(format!("source is not a directory: {}", source.display()).into());
    }

    ensure_unix_mountpoint(mountpoint)?;

    let fs = DirFilesystem::new(source);
    block_on_mount(Box::new(fs), mountpoint, "fsmnt-dir", volname, fsname, 0)
}

/// Everything `mount-image` needs to open and mount an image container.
pub(crate) struct MountImageOptions<'a> {
    /// Image path, or the first segment of an EWF set.
    pub(crate) image: &'a std::path::Path,
    /// Where to attach the mounted volume.
    pub(crate) mountpoint: &'a str,
    /// Partition ordinal to mount, as listed by `fsmnt partitions IMAGE`.
    pub(crate) partition: Option<usize>,
    /// Byte offset of the filesystem; used when no partition is selected.
    pub(crate) offset: u64,
    /// Volume label override.
    pub(crate) volname: Option<&'a str>,
    /// `BitLocker` recovery password, if supplied.
    pub(crate) recovery_password: Option<String>,
    /// `BitLocker` startup-key file, if supplied.
    pub(crate) bek_file: Option<&'a std::path::Path>,
    /// Filesystem-level open options: root selector and journal-replay choice.
    pub(crate) filesystem: fsmnt::device::FilesystemOpenOptions,
}

/// Mount a supported filesystem image container.
pub(crate) fn handle_mount_image(
    options: MountImageOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let image = options.image;
    let drivers = build_registry(options.recovery_password, options.bek_file)?;
    let open_options = fsmnt::ImageOpenOptions::new().with_filesystem_options(options.filesystem);
    let open_options = match options.partition {
        Some(partition) => open_options.with_partition(partition),
        None => open_options.with_offset(options.offset),
    };
    let opened = fsmnt::open_image_with_options(image, &drivers, open_options)?;

    ensure_unix_mountpoint(options.mountpoint)?;

    let volname = options.volname.map_or_else(
        || {
            image
                .file_stem()
                .map_or_else(|| "fsmnt-image".to_string(), |s| s.to_string_lossy().into())
        },
        ToString::to_string,
    );

    println!(
        "Detected {:?} at offset {} in {} image {}",
        opened.detected,
        opened.offset,
        opened.format,
        image.display(),
    );
    block_on_mount(
        opened.filesystem,
        options.mountpoint,
        fs_label(opened.detected),
        &volname,
        fs_label(opened.detected),
        opened.size_bytes,
    )
}

/// Everything `mount-device` needs to open and mount a drive partition.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) struct MountDeviceOptions<'a> {
    /// Drive ID as printed by `fsmnt drives`.
    pub(crate) drive: &'a str,
    /// Partition ordinal over non-empty partition-table entries.
    pub(crate) partition: usize,
    /// Bypass operating-system logical volumes.
    pub(crate) raw: bool,
    /// Explicit logical-volume identifier.
    pub(crate) volume: Option<&'a str>,
    /// Extra raw members as `DRIVE:PARTITION`.
    pub(crate) members: &'a [String],
    /// Where to attach the mounted volume.
    pub(crate) mountpoint: &'a str,
    /// Volume label override.
    pub(crate) volname: Option<&'a str>,
    /// `BitLocker` recovery password, if supplied.
    pub(crate) recovery_password: Option<String>,
    /// `BitLocker` startup-key file, if supplied.
    pub(crate) bek_file: Option<&'a std::path::Path>,
    /// Guest fstab to compose child mounts from.
    pub(crate) fstab: Option<&'a str>,
    /// Filesystem-level open options: root selector and journal-replay choice.
    pub(crate) filesystem: fsmnt::device::FilesystemOpenOptions,
}

/// Mount a partition from a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) fn handle_mount_device(
    options: MountDeviceOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::{
        HostDriveEnumerator, HostDriveId, LogicalVolumeId, SourceOrigin, SourceSelection,
    };

    let id = HostDriveId::new(options.drive);
    let drivers = build_registry(options.recovery_password, options.bek_file)?;

    let selection = if options.raw {
        let additional_partitions = options
            .members
            .iter()
            .map(|member| parse_partition_address(member))
            .collect::<Result<Vec<_>, _>>()?;
        SourceSelection::Raw {
            additional_partitions,
        }
    } else if let Some(volume) = options.volume {
        SourceSelection::Logical(LogicalVolumeId::new(volume))
    } else {
        SourceSelection::Auto
    };
    let open_options = fsmnt::PartitionOpenOptions::new()
        .with_source(selection)
        .with_filesystem_options(options.filesystem);
    let opened = if let Some(fstab) = options.fstab {
        let opened = fsmnt::open_device_partition_with_fstab::<HostDrives>(
            &id,
            options.partition,
            &drivers,
            open_options,
            fstab,
        )?;
        println!("Composed child mounts from {fstab}");
        opened
    } else {
        fsmnt::open_device_partition_with_options::<HostDrives>(
            &id,
            options.partition,
            &drivers,
            open_options,
        )?
    };

    ensure_unix_mountpoint(options.mountpoint)?;

    let volname = options.volname.map_or_else(
        || {
            HostDrives::get_drive_info(&id)
                .ok()
                .and_then(|i| i.model)
                .unwrap_or_else(|| options.drive.to_string())
        },
        ToString::to_string,
    );

    match &opened.source {
        SourceOrigin::Logical(volume) => {
            println!("Opened logical volume {}", volume.id());
        }
        SourceOrigin::Raw(extents) => {
            println!("Opened {} raw physical member(s)", extents.len());
        }
    }

    block_on_mount(
        opened.filesystem,
        options.mountpoint,
        fs_label(opened.detected),
        &volname,
        fs_label(opened.detected),
        opened.size_bytes,
    )
}

/// Parse a `DRIVE:PARTITION` raw-member argument.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) fn parse_partition_address(
    value: &str,
) -> Result<fsmnt::device::PartitionAddress, Box<dyn std::error::Error>> {
    let (drive, partition) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid raw member '{value}'; expected DRIVE:PARTITION"))?;
    if drive.is_empty() {
        return Err(format!("invalid raw member '{value}'; drive ID is empty").into());
    }
    let partition = partition
        .parse::<usize>()
        .map_err(|error| format!("invalid partition ordinal in raw member '{value}': {error}"))?;
    Ok(fsmnt::device::PartitionAddress::new(
        fsmnt::device::HostDriveId::new(drive),
        partition,
    ))
}
