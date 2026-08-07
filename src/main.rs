//! Command-line interface for the `fsmnt` library.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use fsmnt::DirFilesystem;

/// Mount filesystem sources as read-only virtual volumes (FUSE on Unix,
/// Dokan on Windows).
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone, Debug, Default)]
struct FilesystemMountOptions {
    /// Filesystem-owned root to mount: default, top-level, path:PATH,
    /// id:NUMBER, index:NUMBER, name:NAME, or role:ROLE.
    #[arg(long, value_name = "SELECTOR")]
    fs_root: Option<fsmnt::device::FilesystemRoot>,
}

impl FilesystemMountOptions {
    fn root(self) -> fsmnt::device::FilesystemRoot {
        self.fs_root.unwrap_or_default()
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Mount a host directory as a read-only volume.
    Mount {
        /// Source directory to expose.
        source: PathBuf,

        /// Mountpoint: a directory on Unix; a drive letter (e.g. `Z:`) or
        /// empty NTFS directory on Windows.
        mountpoint: String,

        /// Volume label shown in the OS file manager.
        #[arg(long, default_value = "fsmnt")]
        volname: String,

        /// Filesystem type label reported to the OS.
        #[arg(long, default_value = "fsmnt")]
        fsname: String,
    },

    /// Mount a raw filesystem image file (NTFS, FAT, exFAT, ext, APFS, Btrfs,
    /// `BitLocker`) as a read-only volume.
    MountImage {
        /// Path to the image file. Must start with the filesystem itself,
        /// not a partition table; use `--offset` for an image of a whole
        /// partitioned disk.
        image: PathBuf,

        /// Mountpoint: a directory on Unix; a drive letter (e.g. `Z:`) or
        /// empty NTFS directory on Windows.
        mountpoint: String,

        /// Byte offset of the filesystem within the image.
        #[arg(long, default_value_t = 0)]
        offset: u64,

        /// Volume label shown in the OS file manager.
        #[arg(long)]
        volname: Option<String>,

        /// `BitLocker` recovery password (48 digits, hyphen-separated
        /// groups of six).
        #[arg(long)]
        recovery_password: Option<String>,

        /// Path to a `BitLocker` .BEK startup key file.
        #[arg(long)]
        bek_file: Option<PathBuf>,

        #[command(flatten)]
        filesystem: FilesystemMountOptions,
    },

    /// List physical drives on this machine.
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    Drives,

    /// List partitions on a physical drive.
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    Partitions {
        /// Drive ID as shown by `fsmnt drives` (e.g. `0`, `sda`, `disk2`).
        drive: String,
    },

    /// Mount a partition from a physical drive (NTFS, FAT, exFAT, ext, APFS,
    /// Btrfs, `BitLocker`).
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    MountDevice {
        /// Drive ID as shown by `fsmnt drives` (e.g. `0`, `sda`, `disk2`).
        drive: String,

        /// Mountpoint: a directory on Unix; a drive letter (e.g. `Z:`) or
        /// empty NTFS directory on Windows.
        mountpoint: String,

        /// Partition number (0-based index over non-empty entries).
        #[arg(long, default_value_t = 0)]
        partition: usize,

        /// Bypass operating-system logical volumes and read physical
        /// partition members directly.
        #[arg(long, conflicts_with = "volume")]
        raw: bool,

        /// Select an operating-system logical volume by the identifier
        /// reported when automatic selection is ambiguous.
        #[arg(long, value_name = "ID")]
        volume: Option<String>,

        /// Add a raw member as `DRIVE:PARTITION` when automatic discovery
        /// cannot enumerate it. May be repeated and requires `--raw`.
        #[arg(long, value_name = "DRIVE:PARTITION", requires = "raw")]
        member: Vec<String>,

        /// Volume label shown in the OS file manager (defaults to the
        /// drive model or ID).
        #[arg(long)]
        volname: Option<String>,

        /// `BitLocker` recovery password (48 digits, hyphen-separated
        /// groups of six).
        #[arg(long)]
        recovery_password: Option<String>,

        /// Path to a `BitLocker` .BEK startup key file.
        #[arg(long)]
        bek_file: Option<PathBuf>,

        /// Compose child mounts from the selected root's fstab. With no path,
        /// reads /etc/fstab.
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            default_missing_value = "/etc/fstab"
        )]
        fstab: Option<String>,

        #[command(flatten)]
        filesystem: FilesystemMountOptions,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mount {
            source,
            mountpoint,
            volname,
            fsname,
        } => handle_mount(&source, &mountpoint, &volname, &fsname),
        Commands::MountImage {
            image,
            mountpoint,
            offset,
            volname,
            recovery_password,
            bek_file,
            filesystem,
        } => handle_mount_image(
            &image,
            &mountpoint,
            offset,
            volname.as_deref(),
            recovery_password,
            bek_file.as_deref(),
            filesystem.root(),
        ),
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        Commands::Drives => handle_drives(),
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        Commands::Partitions { drive } => handle_partitions(&drive),
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        Commands::MountDevice {
            drive,
            mountpoint,
            partition,
            raw,
            volume,
            member,
            volname,
            recovery_password,
            bek_file,
            fstab,
            filesystem,
        } => handle_mount_device(MountDeviceOptions {
            drive: &drive,
            partition,
            raw,
            volume: volume.as_deref(),
            members: &member,
            mountpoint: &mountpoint,
            volname: volname.as_deref(),
            recovery_password,
            bek_file: bek_file.as_deref(),
            fstab: fstab.as_deref(),
            filesystem_root: filesystem.root(),
        }),
    }
}

/// Mount `source` at `mountpoint` and block until Ctrl+C.
fn handle_mount(
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

/// On Unix the mountpoint is a directory; create it if needed.
#[allow(
    clippy::unnecessary_wraps,
    reason = "fallible only on Unix; single signature keeps call sites clean"
)]
fn ensure_unix_mountpoint(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    if !std::path::Path::new(mountpoint).exists() {
        std::fs::create_dir_all(mountpoint)?;
    }
    #[cfg(not(unix))]
    let _ = mountpoint;
    Ok(())
}

/// Mount `fs` and block until Ctrl+C, printing progress.
fn block_on_mount(
    fs: Box<dyn fsmnt::TargetFilesystem>,
    mountpoint: &str,
    kind: &str,
    volname: &str,
    fsname: &str,
    total_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mp_display = mountpoint.to_string();
    println!("Mounting {kind} volume at {mountpoint}...");
    fsmnt::mount(fs, mountpoint, fsname, volname, total_bytes, move || {
        println!("Volume mounted at {mp_display}. Press Ctrl+C to unmount.");
    })?;
    println!("Unmounted.");
    Ok(())
}

/// Format a byte count for human display.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn format_size(bytes: u64) -> String {
    if bytes == u64::MAX {
        return "unknown".to_string();
    }
    if bytes < 1_000_000_000 {
        return format!("{} MB", bytes / 1_000_000);
    }
    let gb = bytes / 1_000_000_000;
    let tenths = (bytes % 1_000_000_000) / 100_000_000;
    format!("{gb}.{tenths} GB")
}

/// Filesystem type label for a detected boot sector.
fn fs_label(detected: fsmnt::device::DetectedBootSector) -> &'static str {
    use fsmnt::device::DetectedBootSector as D;
    match detected {
        D::Ntfs => "ntfs",
        D::BitLocker => "bitlocker+ntfs",
        D::Fat12 => "fat12",
        D::Fat16 => "fat16",
        D::Fat32 => "fat32",
        D::ExFat => "exfat",
        D::Ext => "extfs",
        D::Apfs => "apfs",
        D::Btrfs => "btrfs",
        D::MbrPartitioned | D::GptPartitioned | D::Unknown => "unknown",
    }
}

/// List physical drives.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn handle_drives() -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::HostDriveEnumerator;

    let drives = HostDrives::enumerate_drives()?;
    if drives.is_empty() {
        println!("No drives found.");
        return Ok(());
    }

    println!(
        "{:<10} {:>12}  {:<10} {:<28} ACCESS",
        "ID", "SIZE", "BUS", "MODEL"
    );
    for d in drives {
        let size = d
            .size_bytes
            .map_or_else(|| "unknown".to_string(), format_size);
        let bus = d
            .bus_type
            .map_or_else(|| "-".to_string(), |b| b.to_string());
        let model = d.model.as_deref().unwrap_or("-");
        let access = if d.accessible {
            "ok".to_string()
        } else {
            format!(
                "inaccessible ({})",
                d.access_error.as_deref().unwrap_or("unknown"),
            )
        };
        println!(
            "{:<10} {size:>12}  {bus:<10} {model:<28} {access}",
            d.id.to_string()
        );
    }
    Ok(())
}

/// List partitions on a drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn handle_partitions(drive: &str) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::{Disk, DiskLayout, HostDriveEnumerator, HostDriveId};

    let id = HostDriveId::new(drive);
    let info = HostDrives::get_drive_info(&id).ok();
    let sector_size = info.as_ref().and_then(|i| i.sector_size).unwrap_or(512);
    let reader = HostDrives::open_drive(&id)?;
    let mut disk = Disk::with_sector_size(reader, sector_size)?;
    let sector = disk.sector_size();

    match disk.layout().clone() {
        DiskLayout::Gpt { header } => {
            println!("GPT disk (sector size {sector})");
            println!("{:>4}  {:<26} {:>12}  FILESYSTEM", "#", "TYPE", "SIZE");
            let count = usize::try_from(header.num_partition_entries.get()).unwrap_or(usize::MAX);
            let mut ordinal = 0;
            for i in 0..count {
                let Ok(entry) = disk.gpt_partition(i) else {
                    continue;
                };
                if entry.is_empty() {
                    continue;
                }
                let offset = entry.start_offset(sector);
                let size = entry.size_bytes(sector);
                let detected = disk.detect_boot_sector_at(offset).ok();
                println!(
                    "{ordinal:>4}  {:<26} {:>12}  {}",
                    entry.type_name().unwrap_or("Unknown"),
                    format_size(size),
                    detected.map_or_else(|| "unreadable".to_string(), |d| format!("{d:?}")),
                );
                ordinal += 1;
            }
        }
        DiskLayout::Mbr { .. } => {
            println!("MBR disk (sector size {sector})");
            println!("{:>4}  {:<10} {:>12}  FILESYSTEM", "#", "TYPE", "SIZE");
            let extents: Vec<(u8, u64, u64)> = disk
                .mbr_partitions()
                .map(|e| {
                    (
                        e.partition_type,
                        e.start_offset(sector),
                        e.size_bytes(sector),
                    )
                })
                .collect();
            for (i, (ptype, offset, size)) in extents.iter().enumerate() {
                let detected = disk.detect_boot_sector_at(*offset).ok();
                println!(
                    "{i:>4}  0x{ptype:02X}       {:>12}  {}",
                    format_size(*size),
                    detected.map_or_else(|| "unreadable".to_string(), |d| format!("{d:?}")),
                );
            }
        }
        DiskLayout::Bare(fs_type) => {
            println!("No partition table; whole disk is {fs_type:?}");
        }
        DiskLayout::Unknown => {
            println!("Unrecognized disk layout.");
        }
    }
    Ok(())
}

/// Build the driver registry, attaching any supplied `BitLocker`
/// credentials.
///
/// Credentials ride on the driver because `FilesystemDriver::open` takes no
/// credentials parameter.  A driver with none still unlocks volumes whose
/// protection is suspended, via the clear key.
fn build_registry(
    recovery_password: Option<String>,
    bek_file: Option<&std::path::Path>,
) -> Result<fsmnt::device::DriverRegistry, Box<dyn std::error::Error>> {
    use fsmnt_drivers::{BitLockerDriver, registry_with_bitlocker};

    let mut bitlocker = BitLockerDriver::new();
    if let Some(password) = recovery_password {
        bitlocker = bitlocker.with_recovery_password(password);
    }
    if let Some(path) = bek_file {
        bitlocker = bitlocker.with_bek_file(
            std::fs::read(path)
                .map_err(|e| format!("failed to read BEK file '{}': {e}", path.display()))?,
        );
    }
    Ok(registry_with_bitlocker(bitlocker))
}

/// Mount a raw filesystem image file.
fn handle_mount_image(
    image: &std::path::Path,
    mountpoint: &str,
    offset: u64,
    volname: Option<&str>,
    recovery_password: Option<String>,
    bek_file: Option<&std::path::Path>,
    filesystem_root: fsmnt::device::FilesystemRoot,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::device::{
        DetectedBootSector, FilesystemOpenOptions, PartitionReader, detect_boot_sector_at,
    };
    use std::io::{Seek, SeekFrom};

    let mut file = std::fs::File::open(image)
        .map_err(|e| format!("failed to open image '{}': {e}", image.display()))?;
    let size = file.metadata()?.len();
    if offset >= size {
        return Err(format!(
            "offset {offset} is past the end of '{}' ({size} bytes)",
            image.display(),
        )
        .into());
    }

    let detected = detect_boot_sector_at(&mut file, offset)?;

    if detected == DetectedBootSector::MbrPartitioned
        || detected == DetectedBootSector::GptPartitioned
    {
        return Err(format!(
            "'{}' is a partitioned disk image ({detected:?}), not a filesystem. \
             Re-run with --offset set to the start of a partition.",
            image.display(),
        )
        .into());
    }

    file.seek(SeekFrom::Start(0))?;
    let reader = PartitionReader::new(file, offset, size - offset);
    let drivers = build_registry(recovery_password, bek_file)?;
    let filesystem = drivers.open_with_options(
        Box::new(reader),
        detected,
        &FilesystemOpenOptions::new().with_root(filesystem_root),
    )?;

    ensure_unix_mountpoint(mountpoint)?;

    let volname = volname.map_or_else(
        || {
            image
                .file_stem()
                .map_or_else(|| "fsmnt-image".to_string(), |s| s.to_string_lossy().into())
        },
        ToString::to_string,
    );

    println!(
        "Detected {detected:?} at offset {offset} in {}",
        image.display()
    );
    block_on_mount(
        filesystem,
        mountpoint,
        fs_label(detected),
        &volname,
        fs_label(detected),
        size - offset,
    )
}

/// Mount a partition from a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
struct MountDeviceOptions<'a> {
    drive: &'a str,
    partition: usize,
    raw: bool,
    volume: Option<&'a str>,
    members: &'a [String],
    mountpoint: &'a str,
    volname: Option<&'a str>,
    recovery_password: Option<String>,
    bek_file: Option<&'a std::path::Path>,
    fstab: Option<&'a str>,
    filesystem_root: fsmnt::device::FilesystemRoot,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn handle_mount_device(options: MountDeviceOptions<'_>) -> Result<(), Box<dyn std::error::Error>> {
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
        .with_filesystem_root(options.filesystem_root);
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

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn parse_partition_address(
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

#[cfg(all(test, any(windows, target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{Cli, Commands, FilesystemMountOptions, Parser, parse_partition_address};
    use fsmnt::device::FilesystemRoot;

    #[test]
    fn raw_member_address_uses_last_colon() {
        let address = parse_partition_address("device:name:3").expect("partition address");
        assert_eq!(address.drive().as_str(), "device:name");
        assert_eq!(address.partition(), 3);
    }

    #[test]
    fn raw_member_requires_raw_flag() {
        let result = Cli::try_parse_from(["fsmnt", "mount-device", "0", "Z:", "--member", "1:0"]);
        assert!(result.is_err());
    }

    #[test]
    fn raw_and_logical_volume_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "0",
            "Z:",
            "--raw",
            "--volume",
            "logical-id",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn filesystem_root_is_parsed_for_device_mounts() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "0",
            "Z:",
            "--raw",
            "--fs-root",
            "path:root/snapshot",
        ])
        .expect("filesystem root path");
        let Commands::MountDevice { filesystem, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(
            filesystem.root(),
            FilesystemRoot::Path("root/snapshot".to_string())
        );
    }

    #[test]
    fn filesystem_root_supports_cross_format_selectors() {
        for (selector, expected) in [
            ("default", FilesystemRoot::Default),
            ("top-level", FilesystemRoot::TopLevel),
            ("id:256", FilesystemRoot::Id(256)),
            ("index:2", FilesystemRoot::Index(2)),
            (
                "name:Macintosh HD - Data",
                FilesystemRoot::Name("Macintosh HD - Data".to_string()),
            ),
            ("role:data", FilesystemRoot::Role("data".to_string())),
        ] {
            let cli =
                Cli::try_parse_from(["fsmnt", "mount-image", "image", "Z:", "--fs-root", selector])
                    .expect("filesystem root selector");
            let Commands::MountImage { filesystem, .. } = cli.command else {
                panic!("wrong command");
            };
            assert_eq!(filesystem.root(), expected);
        }
    }

    #[test]
    fn default_filesystem_root_is_typed() {
        assert_eq!(
            FilesystemMountOptions::default().root(),
            FilesystemRoot::Default
        );
    }

    #[test]
    fn malformed_filesystem_root_is_rejected_by_clap() {
        let result = Cli::try_parse_from([
            "fsmnt",
            "mount-image",
            "image",
            "Z:",
            "--fs-root",
            "subvolume-without-a-selector-kind",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn fstab_flag_defaults_to_the_selected_roots_table() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "1",
            "Z:",
            "--raw",
            "--fstab",
            "--fs-root",
            "path:root",
        ])
        .expect("fstab mount");
        let Commands::MountDevice { fstab, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(fstab.as_deref(), Some("/etc/fstab"));
    }

    #[test]
    fn fstab_flag_accepts_a_custom_guest_path() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "1",
            "Z:",
            "--fstab",
            "/etc/fstab.forensic",
        ])
        .expect("custom fstab mount");
        let Commands::MountDevice { fstab, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(fstab.as_deref(), Some("/etc/fstab.forensic"));
    }
}
