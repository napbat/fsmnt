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

/// Filesystem-level choices shared by the mounting subcommands.
#[derive(Args, Clone, Debug, Default)]
struct FilesystemMountOptions {
    /// Filesystem-owned root to mount (Btrfs and APFS only — the
    /// single-root formats NTFS, FAT, exFAT, ext and `BitLocker` accept just
    /// `default`): default, top-level, path:PATH, id:NUMBER, index:NUMBER,
    /// name:NAME, or role:ROLE.
    #[arg(long, value_name = "SELECTOR")]
    fs_root: Option<fsmnt::device::FilesystemRoot>,

    /// Present the volume exactly as it sits on disk: skip ext journal and
    /// orphan replay. Replay only ever builds an in-memory overlay — the
    /// source is never written either way — so this selects the raw view
    /// over the recovered one, e.g. to compare against carving results.
    #[arg(long)]
    no_journal_replay: bool,

    /// Open an ext volume through the metadata backed up in this block
    /// group instead of the primary copy at the start (ext keeps copies in
    /// groups 1, 3, 5, 7, 9, 25, … — the same escape hatch as
    /// `e2fsck -b`). Use when the primary superblock or group-descriptor
    /// table is damaged.
    #[arg(long, value_name = "GROUP")]
    backup_superblock: Option<u32>,

    /// Recover ext files whose directory tree is damaged or missing: mount
    /// anyway and add a `.fsmnt-salvage` directory listing every in-use
    /// inode found by sweeping the readable block groups as `inode-N`.
    #[arg(long)]
    salvage: bool,

    /// Keep reading when the source cannot deliver a sector: bytes past the
    /// end of a truncated image (up to the partition's declared extent) and
    /// sectors that fail with an I/O error are served as zeros instead of
    /// failing the read, so what exists can still be copied out. Every
    /// substituted byte is counted and reported when the mount ends. Off by
    /// default: zeros are not data.
    #[arg(long)]
    best_effort_reads: bool,
}

impl FilesystemMountOptions {
    /// The requested root, or the driver's own default.
    fn root(&self) -> fsmnt::device::FilesystemRoot {
        self.fs_root.clone().unwrap_or_default()
    }

    /// The driver-facing open options these flags describe.
    fn open_options(&self) -> fsmnt::device::FilesystemOpenOptions {
        fsmnt::device::FilesystemOpenOptions::new()
            .with_root(self.root())
            .with_journal_replay(!self.no_journal_replay)
            .with_ext_backup_superblock(self.backup_superblock)
            .with_salvage(self.salvage)
    }
}

/// Shared option for the commands that mount something.
#[derive(Args, Clone, Debug, Default)]
struct DetachOption {
    /// Mount in a background process and return as soon as the volume is
    /// ready, instead of blocking until it is unmounted. Stop it later with
    /// `fsmnt unmount MOUNTPOINT`.
    #[arg(long)]
    detach: bool,
}

impl DetachOption {
    /// Whether this command should hand its mount to a background
    /// process. The background process runs the same command with the
    /// flag removed, so it always mounts in the foreground itself.
    fn requested(&self) -> bool {
        self.detach && !cli::detach::is_background_mount()
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

        #[command(flatten)]
        detach: DetachOption,
    },

    /// Unmount a volume, from anywhere.
    ///
    /// Works from another shell while a mount command is blocking, which
    /// then returns. On Windows it also restores a mountpoint directory
    /// left behind by a mount process that was killed.
    #[command(alias = "umount")]
    Unmount {
        /// Mountpoint to release: the directory on Unix; the drive letter
        /// (e.g. `Z:`) or directory on Windows.
        mountpoint: String,
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

        /// Offset of the filesystem within the image, for media no partition
        /// table describes: bytes (`270532608`), a binary or decimal
        /// multiple (`258MiB`, `1M`, `270MB`), or sectors of
        /// `--sector-size` (`528384s`). `fsmnt scan IMAGE` finds them.
        #[arg(
            long,
            value_name = "SIZE",
            value_parser = cli::size::parse_size_expr,
            default_value = "0"
        )]
        offset: cli::size::SizeExpr,

        /// Logical sector size of the imaged drive, in bytes (a power of two
        /// of at least 512). Sets the unit for an `s`-suffixed `--offset`
        /// and the unit the image's GPT/MBR is read in — a dump of a 4Kn
        /// drive needs 4096. Detected when omitted.
        #[arg(long, value_name = "BYTES", value_parser = cli::size::parse_sector_size)]
        sector_size: Option<u32>,

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

        #[command(flatten)]
        detach: DetachOption,
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

        /// Logical sector size the partition table is written in, in bytes
        /// (a power of two of at least 512). A dump of a 4Kn drive needs
        /// 4096; without this, 512 is tried first and 4096 second.
        #[arg(long, value_name = "BYTES", value_parser = cli::size::parse_sector_size)]
        sector_size: Option<u32>,
    },

    /// Search an image for filesystems, wherever they sit.
    ///
    /// For media with no partition table, a corrupt one, or one that
    /// disagrees with the bytes: reads the image once and reports every
    /// offset that starts a filesystem, ready to pass to
    /// `mount-image --offset`. ext backup superblocks are reported as
    /// evidence for their filesystem, including the start they imply when
    /// the primary is gone.
    Scan {
        /// Image path or first EWF segment.
        image: PathBuf,

        /// Distance between candidate offsets, in bytes. Filesystems start
        /// on a block boundary, so the 4 KiB default finds them; use 512 to
        /// search harder at eight times the cost.
        #[arg(long, value_name = "BYTES", default_value_t = fsmnt::DEFAULT_STRIDE)]
        stride: u64,

        /// Logical sector size the offsets are also reported in.
        #[arg(long, value_name = "BYTES", value_parser = cli::size::parse_sector_size)]
        sector_size: Option<u32>,
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

        #[command(flatten)]
        detach: DetachOption,
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

impl Commands {
    /// The mountpoint to wait for when this command hands its mount to a
    /// background process, or `None` when it runs in the foreground.
    fn detached_mountpoint(&self) -> Option<&str> {
        let (detach, mountpoint) = match self {
            Self::Mount {
                detach, mountpoint, ..
            }
            | Self::MountImage {
                detach, mountpoint, ..
            } => (detach, mountpoint),
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Self::MountDevice {
                detach, mountpoint, ..
            } => (detach, mountpoint),
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            Self::Drives => return None,
            Self::Partitions { .. } | Self::Scan { .. } | Self::Unmount { .. } => return None,
        };
        detach.requested().then_some(mountpoint.as_str())
    }
}

/// Parse the command line and dispatch to the selected subcommand.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // `--detach`: hand the whole command to a background process and wait
    // here only until its volume is live.
    if let Some(mountpoint) = cli.command.detached_mountpoint() {
        let pid = cli::detach::spawn(mountpoint)?;
        println!(
            "Volume mounted at {mountpoint} (pid {pid}); run 'fsmnt unmount {mountpoint}' to unmount."
        );
        return Ok(());
    }

    match cli.command {
        Commands::Mount {
            source,
            mountpoint,
            volname,
            fsname,
            detach: _,
        } => cli::handle_mount(&source, &mountpoint, &volname, &fsname),
        Commands::Unmount { mountpoint } => cli::handle_unmount(&mountpoint),
        Commands::MountImage {
            image,
            mountpoint,
            partition,
            offset,
            sector_size,
            volname,
            recovery_password,
            bek_file,
            filesystem,
            detach: _,
        } => cli::handle_mount_image(cli::MountImageOptions {
            image: &image,
            mountpoint: &mountpoint,
            partition,
            offset,
            sector_size,
            volname: volname.as_deref(),
            recovery_password,
            bek_file: bek_file.as_deref(),
            filesystem: filesystem.open_options(),
            best_effort_reads: filesystem.best_effort_reads,
        }),
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        Commands::Drives => cli::handle_drives(),
        Commands::Partitions {
            target,
            sector_size,
        } => cli::handle_partitions(&target, sector_size),
        Commands::Scan {
            image,
            stride,
            sector_size,
        } => cli::handle_scan(&cli::ScanImageOptions {
            image: &image,
            stride,
            sector_size,
        }),
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
            detach: _,
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
            filesystem: filesystem.open_options(),
            best_effort_reads: filesystem.best_effort_reads,
        }),
    }
}
