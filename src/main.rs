//! Command-line interface for the `fsmnt` library.
//!
//! This file holds the clap definitions and the dispatch from a parsed
//! command to its handler; the handlers themselves live in [`cli`].

mod cli;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Mount filesystem sources as read-only virtual volumes (FUSE on Unix,
/// Dokan on Windows).
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Filesystem-root selection shared by the mounting subcommands.
#[derive(Args, Clone, Debug, Default)]
struct FilesystemMountOptions {
    /// Filesystem-owned root to mount: default, top-level, path:PATH,
    /// id:NUMBER, index:NUMBER, name:NAME, or role:ROLE.
    #[arg(long, value_name = "SELECTOR")]
    fs_root: Option<fsmnt::device::FilesystemRoot>,
}

impl FilesystemMountOptions {
    /// The requested root, or the driver's own default.
    fn root(self) -> fsmnt::device::FilesystemRoot {
        self.fs_root.unwrap_or_default()
    }
}

/// The `fsmnt` subcommands.
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

    /// Mount a raw, EWF, VHD, or VHDX image (NTFS, FAT, exFAT, ext, APFS,
    /// Btrfs, `BitLocker`) as a read-only volume.
    MountImage {
        /// Image path or first EWF segment (`.E01`/`.Ex01`). VHD/VHDX
        /// differencing parents are resolved automatically. A whole-disk
        /// image needs `--partition N` (list them with
        /// `fsmnt partitions IMAGE`) or `--offset`; without either, the
        /// decoded media must start with a filesystem.
        image: PathBuf,

        /// Mountpoint: a directory on Unix; a drive letter (e.g. `Z:`) or
        /// empty NTFS directory on Windows.
        mountpoint: String,

        /// Partition to mount, as numbered by `fsmnt partitions IMAGE`
        /// (0-based index over non-empty entries).
        #[arg(long, conflicts_with = "offset")]
        partition: Option<usize>,

        /// Byte offset of the filesystem within the image, for media no
        /// partition table describes.
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

    /// List the partitions of a physical drive or a disk image.
    Partitions {
        /// Drive ID as shown by `fsmnt drives` (e.g. `0`, `sda`, `disk2`),
        /// or the path to a raw, EWF, VHD, or VHDX image. Anything that
        /// names an existing file, contains a path separator, or has a file
        /// extension is treated as an image.
        target: String,
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

/// Run the selected subcommand, reporting failures by message.
///
/// Returning the error from `main` would print its `Debug` form, which hides
/// the guidance the error messages carry (which partition to pick, which
/// credential is missing) behind a struct dump.
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parse the command line and dispatch to the selected subcommand.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mount {
            source,
            mountpoint,
            volname,
            fsname,
        } => cli::handle_mount(&source, &mountpoint, &volname, &fsname),
        Commands::MountImage {
            image,
            mountpoint,
            partition,
            offset,
            volname,
            recovery_password,
            bek_file,
            filesystem,
        } => cli::handle_mount_image(cli::MountImageOptions {
            image: &image,
            mountpoint: &mountpoint,
            partition,
            offset,
            volname: volname.as_deref(),
            recovery_password,
            bek_file: bek_file.as_deref(),
            filesystem_root: filesystem.root(),
        }),
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        Commands::Drives => cli::handle_drives(),
        Commands::Partitions { target } => cli::handle_partitions(&target),
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
        } => cli::handle_mount_device(cli::MountDeviceOptions {
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
