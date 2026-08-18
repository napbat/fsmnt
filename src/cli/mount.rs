//! The `mount` subcommand: one option set, three kinds of source.
//!
//! Resolving the source comes first, because it decides which options mean
//! anything ([`check_options`]) and which opener runs. Locating the
//! filesystem inside it is then the same question for an image and a drive
//! — a partition ordinal, a scanned ordinal, or a byte offset — and only
//! the function that answers it differs.

use std::path::Path;

use tracing::info;

use fsmnt::DirFilesystem;

use super::size::DEFAULT_SECTOR_SIZE;
use super::source::{Source, SourceKind, check_applicability, resolve};
use super::{
    block_on_mount, build_registry, ensure_unix_mountpoint, fs_label, warn_if_truncated,
    warn_layout_origin,
};
use crate::MountArgs;

/// Options that describe a filesystem inside a medium: an image or a drive,
/// never a host directory that already is one.
const MEDIA: &[SourceKind] = &[SourceKind::Image, SourceKind::Drive];

/// Options that only exist because an operating system has its own view of
/// a drive's partitions.
const DRIVE_ONLY: &[SourceKind] = &[SourceKind::Drive];

/// Mount whatever `SOURCE` names, and block until the volume is released.
///
/// # Errors
///
/// Returns an error if the source cannot be resolved, an option does not
/// apply to what it resolved to, the filesystem cannot be located or
/// opened, or the mount backend refuses the mountpoint.
pub(crate) fn handle_mount(args: &MountArgs) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve(&args.source, args.source_kind())?;
    check_options(args, &source)?;
    match &source {
        Source::Directory(path) => mount_directory(args, path),
        Source::Image(path) => mount_image(args, &source, path),
        Source::Drive(drive) => mount_drive(args, &source, drive),
    }
}

/// Refuse the options this source kind has no use for.
///
/// clap already rejects the combinations that are wrong on their own
/// (`--offset` with `--partition`, `--member` without `--raw`); this is the
/// other half, where the option is fine but the source is not the kind it
/// was written for.
pub(super) fn check_options(
    args: &MountArgs,
    source: &Source,
) -> Result<(), Box<dyn std::error::Error>> {
    check_applicability(
        source,
        &[
            ("--partition", args.partition.is_some(), MEDIA),
            ("--offset", args.offset.is_some(), MEDIA),
            ("--scan", args.scan, MEDIA),
            ("--sector-size", args.sector_size.is_some(), MEDIA),
            ("--raw", args.raw, DRIVE_ONLY),
            ("--volume", args.volume.is_some(), DRIVE_ONLY),
            ("--member", !args.member.is_empty(), DRIVE_ONLY),
            ("--fstab", args.fstab.is_some(), MEDIA),
            (
                "--recovery-password",
                args.recovery_password.is_some(),
                MEDIA,
            ),
            ("--bek-file", args.bek_file.is_some(), MEDIA),
            ("--fs-root", args.filesystem.fs_root.is_some(), MEDIA),
            (
                "--no-journal-replay",
                args.filesystem.no_journal_replay,
                MEDIA,
            ),
            (
                "--backup-superblock",
                args.filesystem.backup_superblock.is_some(),
                MEDIA,
            ),
            ("--salvage", args.filesystem.salvage, MEDIA),
            (
                "--best-effort-reads",
                args.filesystem.best_effort_reads,
                MEDIA,
            ),
        ],
    )
}

/// Expose a host directory as a volume of its own.
fn mount_directory(args: &MountArgs, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    ensure_unix_mountpoint(&args.mountpoint)?;

    let volname = args.volname.clone().unwrap_or_else(|| {
        path.file_name().map_or_else(
            || "fsmnt".to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    });
    block_on_mount(
        Box::new(DirFilesystem::new(path)),
        &args.mountpoint,
        "directory",
        &volname,
        args.fsname.as_deref().unwrap_or("fsmnt-dir"),
        0,
        None,
    )
}

/// Mount a filesystem inside a raw, EWF, VHD, or VHDX image.
fn mount_image(
    args: &MountArgs,
    source: &Source,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let drivers = build_registry(args.recovery_password.clone(), args.bek_file.as_deref())?;
    let mut options = fsmnt::ImageOpenOptions::new()
        .with_filesystem_options(args.filesystem.open_options())
        .with_best_effort_reads(args.filesystem.best_effort_reads);
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    if args.scan {
        options = options.with_scan(args.stride);
    }
    options = match args.partition {
        Some(partition) => options.with_partition(partition),
        None => options.with_offset(requested_offset(args)?),
    };

    let opened = match args.fstab.as_deref() {
        Some(fstab) => {
            let opened = fsmnt::open_image_with_fstab(path, &drivers, options, fstab)?;
            info!("composed child mounts from {fstab}");
            opened
        }
        None => fsmnt::open_image_with_options(path, &drivers, options)?,
    };

    ensure_unix_mountpoint(&args.mountpoint)?;

    let volname = args.volname.clone().unwrap_or_else(|| {
        path.file_stem().map_or_else(
            || "fsmnt-image".to_string(),
            |stem| stem.to_string_lossy().into_owned(),
        )
    });
    let label = fs_label(opened.detected);

    info!(
        "detected {:?} at offset {} in {} image {}",
        opened.detected,
        opened.offset,
        opened.format,
        path.display(),
    );
    warn_layout_origin(opened.layout_origin, args.partition, source);
    warn_if_truncated(opened.truncated_by, opened.size_bytes, "image");
    block_on_mount(
        opened.filesystem,
        &args.mountpoint,
        label,
        &volname,
        args.fsname.as_deref().unwrap_or(label),
        opened.size_bytes,
        opened.substitutions,
    )
}

/// The byte offset `--offset` asks for, or the start of the media.
fn requested_offset(args: &MountArgs) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(offset) = args.offset else {
        return Ok(0);
    };
    Ok(offset.resolve(args.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE))?)
}

/// Mount a filesystem on a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn mount_drive(
    args: &MountArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::{HostDriveEnumerator, LogicalVolumeId, SourceOrigin, SourceSelection};

    let drivers = build_registry(args.recovery_password.clone(), args.bek_file.as_deref())?;
    let selection = if args.raw {
        SourceSelection::Raw {
            additional_partitions: args
                .member
                .iter()
                .map(|member| parse_partition_address(member))
                .collect::<Result<Vec<_>, _>>()?,
        }
    } else if let Some(volume) = args.volume.as_deref() {
        SourceSelection::Logical(LogicalVolumeId::new(volume))
    } else {
        SourceSelection::Auto
    };
    let mut options = fsmnt::PartitionOpenOptions::new()
        .with_source(selection)
        .with_filesystem_options(args.filesystem.open_options())
        .with_best_effort_reads(args.filesystem.best_effort_reads);
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    if args.scan {
        options = options.with_scan(args.stride);
    }

    let opened = open_drive_location(args, source, drive, &drivers, options)?;

    ensure_unix_mountpoint(&args.mountpoint)?;

    let volname = args.volname.clone().unwrap_or_else(|| {
        HostDrives::get_drive_info(drive)
            .ok()
            .and_then(|info| info.model)
            .unwrap_or_else(|| drive.to_string())
    });
    match &opened.source {
        SourceOrigin::Logical(volume) => info!("opened logical volume {}", volume.id()),
        SourceOrigin::Raw(extents) => info!("opened {} raw physical member(s)", extents.len()),
    }

    let label = fs_label(opened.detected);
    warn_layout_origin(opened.layout_origin, args.partition, source);
    warn_if_truncated(opened.truncated_by, opened.size_bytes, "partition");
    block_on_mount(
        opened.filesystem,
        &args.mountpoint,
        label,
        &volname,
        args.fsname.as_deref().unwrap_or(label),
        opened.size_bytes,
        opened.substitutions,
    )
}

/// Open the drive at whichever location the command line named.
///
/// A byte offset reads the drive physically, so no partition table is
/// consulted and no logical volume exists; an ordinal — from the table or
/// from a scan — goes through the ordinary partition opener. With neither,
/// the drive has to start with a filesystem itself.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn open_drive_location(
    args: &MountArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
    drivers: &fsmnt::device::DriverRegistry,
    options: fsmnt::PartitionOpenOptions,
) -> Result<fsmnt::OpenedPartition, Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;

    if let Some(offset) = args.offset {
        // The image composer accepts any location because it re-derives the
        // siblings from the layout; the device one is written against an
        // ordinal, and an offset is not one.
        if args.fstab.is_some() {
            return Err(
                "--fstab needs a partition ordinal on a drive; use --partition (list them with \
                 `fsmnt partitions DRIVE`)"
                    .into(),
            );
        }
        let offset = offset.resolve(args.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE))?;
        return fsmnt::open_device_at_offset::<HostDrives>(drive, offset, drivers, options);
    }

    let partition = match args.partition {
        Some(partition) => partition,
        None => whole_drive_partition(args, source, drive)?,
    };
    match args.fstab.as_deref() {
        Some(fstab) => {
            let opened = fsmnt::open_device_partition_with_fstab::<HostDrives>(
                drive, partition, drivers, options, fstab,
            )?;
            info!("composed child mounts from {fstab}");
            Ok(opened)
        }
        None => fsmnt::open_device_partition_with_options::<HostDrives>(
            drive, partition, drivers, options,
        ),
    }
}

/// The ordinal to open when the caller named no location at all.
///
/// An unpartitioned drive is mounted whole, exactly as an unpartitioned
/// image is. A partitioned one is refused rather than guessed at: the old
/// `mount-device` default of partition 0 usually landed on the EFI system
/// partition, which is a 100 MB FAT nobody asked for.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn whole_drive_partition(
    args: &MountArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<usize, Box<dyn std::error::Error>> {
    use fsmnt::{DriveLayoutOptions, HostDrives, LayoutKind};

    let mut options = DriveLayoutOptions::new();
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    let layout = fsmnt::drive_layout::<HostDrives>(drive, options)?;
    let table = match layout.kind {
        LayoutKind::Bare(_) | LayoutKind::Unknown | LayoutKind::Scanned => return Ok(0),
        LayoutKind::Gpt => "GPT",
        LayoutKind::Mbr => "MBR",
    };
    Err(format!(
        "{source} contains a {table} partition table; select a partition with `--partition N` \
         (see `fsmnt partitions {source}`)"
    )
    .into())
}

/// Physical drives cannot be opened on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn mount_drive(
    _args: &MountArgs,
    _source: &Source,
    _drive: &fsmnt::device::HostDriveId,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
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
