//! Command-line interface for the `fsmnt` library.
//!
//! This file holds the clap definitions and the dispatch from a parsed
//! command to its handler; the handlers themselves live in [`cli`].
//!
//! Every command takes one `SOURCE`, spelled the same way whether it is a
//! directory, a disk image, or a drive ([`cli::source`]), so the way you say
//! *where the bytes are* does not change with what is holding them. Which
//! options a source kind accepts is checked after it is resolved, in
//! [`cli::mount`], rather than encoded as a separate subcommand per kind.
//!
//! Who is reading is one global flag, not a separate command tree:
//! `--json` ([`cli::logging::LogOptions`]) turns every handler's output into
//! the documents in [`cli::output`], and is carried to them as a
//! [`cli::output::Output`] rather than consulted anywhere below the CLI.

mod cli;

use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgGroup, Args, Parser, Subcommand};

use cli::logging::LogOptions;
use cli::size::{SignedSizeExpr, parse_sector_size, parse_signed_size_expr};

/// Mount filesystem sources as read-only virtual volumes (FUSE on Unix,
/// Dokan on Windows).
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    log: LogOptions,

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

    /// fscrypt master key to unlock encrypted files and filenames with.
    /// Repeatable; applies to every fscrypt-capable filesystem the drivers
    /// support (today ext4, which is what Android's file-based encryption
    /// runs on).
    ///
    /// Spelled `<HEX>` or `v2:<HEX>` for a v2 key (16–64 bytes as 32–128
    /// hex digits), `v1:<DESCRIPTOR>:<HEX>` for a v1 key (the descriptor is
    /// the 16 hex digits the policy stores; the key must be 64 bytes), or
    /// `@<PATH>` in place of `<HEX>` in either form to read the raw key
    /// bytes from a file. A v2 key needs no identifier: the kernel derives
    /// it from the key, and so does fsmnt.
    ///
    /// These are the raw fscrypt master keys, not a PIN, password or
    /// keystore blob. On Android they are the `key` bytes vold keeps
    /// unwrapped in the kernel keyring — read from a live rooted device
    /// with `keyctl` / `fscryptctl`, or reconstructed from
    /// `/data/unencrypted/key` plus `/data/misc/vold/user_keys` where the
    /// wrapping keymaster is software. Keys bound to a TEE or `StrongBox`
    /// cannot be recovered from an image at all.
    ///
    /// Mounting without them still works: the volume opens, encrypted
    /// names appear in the kernel's no-key form, and the mount reports
    /// which key identifiers it is asking for.
    #[arg(long, value_name = "SPEC", value_parser = fsmnt::device::FscryptKeySpec::from_str)]
    fscrypt_key: Vec<fsmnt::device::FscryptKeySpec>,

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
            .with_fscrypt_keys(self.fscrypt_key.clone())
    }
}

/// Shared option for the commands that mount something.
#[derive(Args, Clone, Debug, Default)]
struct DetachOption {
    /// Mount in a background process and return as soon as the volume is
    /// ready, instead of blocking until it is unmounted. Stop it later with
    /// `fsmnt unmount MOUNTPOINT`. `--log-file` is kept, so a background
    /// mount that fails can still say why.
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
    /// List physical drives on this machine.
    Drives,

    /// List the partitions of a drive or a disk image.
    Partitions(PartitionsArgs),

    /// Search a drive or a disk image for filesystems, wherever they sit.
    ///
    /// For media with no partition table, a corrupt one, or one that
    /// disagrees with the bytes: reads the source once and reports every
    /// offset that starts a filesystem, ready to pass to
    /// `fsmnt mount SOURCE --offset`. ext backup superblocks are reported
    /// as evidence for their filesystem, including the start they imply
    /// when the primary is gone.
    Scan(ScanArgs),

    /// Mount a directory, a disk image, or a drive as a read-only volume.
    ///
    /// Images are raw, EWF (`.E01`/`.Ex01`), VHD or VHDX; drives are read
    /// through the operating system's logical volume unless `--raw` says
    /// otherwise. With neither `--partition` nor `--offset` the source must
    /// itself start with a filesystem: an unpartitioned image or drive is
    /// mounted whole, a partitioned one is refused with the command that
    /// lists its partitions.
    // Boxed because this variant carries every mount option there is and
    // the others carry almost none; without it every `Commands` value would
    // be as large as the largest one.
    Mount(Box<MountArgs>),

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
}

/// Everything `fsmnt mount` accepts.
///
/// One option set for all three source kinds; which of them a given source
/// can use is checked once the source is resolved (see
/// [`cli::mount::handle_mount`]), so the error names the option and what the
/// source turned out to be instead of hiding the option in another command.
#[derive(Args, Clone, Debug)]
#[command(group = ArgGroup::new("source_kind").multiple(false))]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is one command-line flag, which clap represents as a bool; \
              the alternative the lint suggests cannot be expressed in an Args derive"
)]
struct MountArgs {
    /// What to mount: a directory, the path to a raw/EWF/VHD/VHDX image, or
    /// a drive — the ID `fsmnt drives` prints (`0`, `sda`, `disk2`) or its
    /// device path (`\\.\PhysicalDrive0`, `/dev/sda`, `/dev/disk2`). Taken
    /// in that order: an existing directory, an existing file, a device
    /// path, then anything with a path separator or a file extension is an
    /// image and a bare token is a drive ID.
    source: String,

    /// Mountpoint: a directory on Unix; a drive letter (e.g. `Z:`) or
    /// empty NTFS directory on Windows.
    mountpoint: String,

    /// Read SOURCE as a host directory whatever it looks like.
    #[arg(long, group = "source_kind")]
    dir: bool,

    /// Read SOURCE as a disk image path without consulting the filesystem,
    /// so a path that is wrong fails as an image and names the file.
    #[arg(long, group = "source_kind")]
    image: bool,

    /// Read SOURCE as a physical drive; a device path is normalised to the
    /// ID `fsmnt drives` prints.
    #[arg(long, group = "source_kind")]
    drive: bool,

    /// Partition to mount, as numbered by `fsmnt partitions SOURCE`
    /// (0-based index over non-empty entries). Images and drives.
    #[arg(long, conflicts_with = "offset")]
    partition: Option<usize>,

    /// Offset of the filesystem within the source, for media no partition
    /// table describes: bytes (`270532608`), a binary or decimal multiple
    /// (`258MiB`, `1M`, `270MB`), or sectors of `--sector-size`
    /// (`528384s`). On a drive this is a physical offset, past any logical
    /// volume the operating system lays over it. A NEGATIVE offset
    /// (`-469762048`, `-448MiB`) reverses the relationship: the medium
    /// begins that many bytes into the filesystem, which is what `fsmnt
    /// scan SOURCE` prints for a slice cut out of a larger volume. `fsmnt
    /// scan SOURCE` finds them. Images and drives.
    #[arg(
        long,
        value_name = "SIZE",
        value_parser = parse_signed_size_expr,
        conflicts_with = "partition",
        allow_hyphen_values = true
    )]
    offset: Option<SignedSizeExpr>,

    /// Resolve `--partition` against a SYNTHETIC table reconstructed by
    /// scanning the media for filesystem starts (`fsmnt partitions SOURCE
    /// --scan` shows it), ignoring any partition table the source carries.
    /// The ordinal is then "the N-th filesystem the scan finds" — valid
    /// only for this source at this stride. Images and drives.
    #[arg(long, requires = "partition", conflicts_with = "offset")]
    scan: bool,

    /// Distance in bytes between the positions `--scan` tests (a
    /// filesystem that starts off a 4 KiB boundary needs 512).
    #[arg(long, value_name = "BYTES", requires = "scan", default_value_t = fsmnt::DEFAULT_STRIDE)]
    stride: u64,

    /// Logical sector size of the media, in bytes (a power of two of at
    /// least 512). Sets the unit for an `s`-suffixed `--offset` and the
    /// unit the GPT/MBR is read in — a dump of a 4Kn drive, or a 4Kn drive
    /// the operating system reports as 512e, needs 4096. Detected, or taken
    /// from the drive, when omitted. Images and drives.
    #[arg(long, value_name = "BYTES", value_parser = parse_sector_size)]
    sector_size: Option<u32>,

    /// Bypass operating-system logical volumes and read physical partition
    /// members directly. Drives only.
    #[arg(long)]
    raw: bool,

    /// Select an operating-system logical volume by the identifier the
    /// VOLUME column of `fsmnt partitions DRIVE` prints, for when automatic
    /// selection is ambiguous. Drives only.
    #[arg(long, value_name = "ID", conflicts_with_all = ["raw", "offset", "scan"])]
    volume: Option<String>,

    /// Add a raw member as `DRIVE:PARTITION` when automatic discovery
    /// cannot enumerate it. May be repeated and requires `--raw`. Drives
    /// only.
    #[arg(long, value_name = "DRIVE:PARTITION", requires = "raw")]
    member: Vec<String>,

    /// Compose child mounts from the selected root's fstab. With no path,
    /// reads /etc/fstab. Children come from the other partitions of the
    /// same image, or from the partitions of every host drive. Images and
    /// drives.
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "/etc/fstab"
    )]
    fstab: Option<String>,

    /// Volume label shown in the OS file manager. Defaults to the directory
    /// name, the image file stem, or the drive model.
    #[arg(long)]
    volname: Option<String>,

    /// Filesystem type label reported to the OS. Defaults to `fsmnt-dir`
    /// for a directory, and to the detected filesystem (`ntfs`, `fat32`,
    /// `extfs`, …) for an image or a drive.
    #[arg(long)]
    fsname: Option<String>,

    /// `BitLocker` recovery password (48 digits, hyphen-separated groups of
    /// six). Images and drives.
    #[arg(long)]
    recovery_password: Option<String>,

    /// Path to a `BitLocker` .BEK startup key file. Images and drives.
    #[arg(long)]
    bek_file: Option<PathBuf>,

    #[command(flatten)]
    filesystem: FilesystemMountOptions,

    #[command(flatten)]
    detach: DetachOption,
}

/// Everything `fsmnt partitions` accepts.
#[derive(Args, Clone, Debug)]
#[command(group = ArgGroup::new("source_kind").multiple(false))]
struct PartitionsArgs {
    /// Drive ID as shown by `fsmnt drives` (e.g. `0`, `sda`, `disk2`) or
    /// its device path, or the path to a raw, EWF, VHD, or VHDX image.
    /// Anything that names an existing file, contains a path separator, or
    /// has a file extension is read as an image.
    source: String,

    /// Read SOURCE as a disk image path without consulting the filesystem.
    #[arg(long, group = "source_kind")]
    image: bool,

    /// Read SOURCE as a physical drive; a device path is normalised to the
    /// ID `fsmnt drives` prints.
    #[arg(long, group = "source_kind")]
    drive: bool,

    /// Logical sector size the partition table is written in, in bytes (a
    /// power of two of at least 512). A dump of a 4Kn drive needs 4096;
    /// without this, an image tries 512 first and 4096 second, and a drive
    /// uses the size the operating system reports.
    #[arg(long, value_name = "BYTES", value_parser = parse_sector_size)]
    sector_size: Option<u32>,

    /// Ignore the source's partition table and print a SYNTHETIC one
    /// reconstructed by scanning the media for filesystem starts. Its
    /// numbering is what `fsmnt mount --scan --partition N` uses.
    #[arg(long)]
    scan: bool,

    /// Distance in bytes between the positions `--scan` tests (a
    /// filesystem that starts off a 4 KiB boundary needs 512).
    #[arg(long, value_name = "BYTES", requires = "scan", default_value_t = fsmnt::DEFAULT_STRIDE)]
    stride: u64,
}

/// Everything `fsmnt scan` accepts.
#[derive(Args, Clone, Debug)]
#[command(group = ArgGroup::new("source_kind").multiple(false))]
struct ScanArgs {
    /// Drive ID as shown by `fsmnt drives` or its device path, or the path
    /// to a raw, EWF, VHD, or VHDX image.
    source: String,

    /// Read SOURCE as a disk image path without consulting the filesystem.
    #[arg(long, group = "source_kind")]
    image: bool,

    /// Read SOURCE as a physical drive; a device path is normalised to the
    /// ID `fsmnt drives` prints.
    #[arg(long, group = "source_kind")]
    drive: bool,

    /// Distance between candidate offsets, in bytes. Filesystems start on a
    /// block boundary, so the 4 KiB default finds them; use 512 to search
    /// harder at eight times the cost.
    #[arg(long, value_name = "BYTES", default_value_t = fsmnt::DEFAULT_STRIDE)]
    stride: u64,

    /// Logical sector size the offsets are also reported in.
    #[arg(long, value_name = "BYTES", value_parser = parse_sector_size)]
    sector_size: Option<u32>,
}

impl MountArgs {
    /// Which kind of source the command line stated, if it stated one.
    fn source_kind(&self) -> cli::source::SourceKind {
        cli::source::SourceKind::from_flags(self.dir, self.image, self.drive)
    }
}

impl PartitionsArgs {
    /// Which kind of source the command line stated, if it stated one.
    fn source_kind(&self) -> cli::source::SourceKind {
        cli::source::SourceKind::from_flags(false, self.image, self.drive)
    }
}

impl ScanArgs {
    /// Which kind of source the command line stated, if it stated one.
    fn source_kind(&self) -> cli::source::SourceKind {
        cli::source::SourceKind::from_flags(false, self.image, self.drive)
    }
}

impl Commands {
    /// The mountpoint to wait for when this command hands its mount to a
    /// background process, or `None` when it runs in the foreground.
    fn detached_mountpoint(&self) -> Option<&str> {
        match self {
            Self::Mount(args) => args.detach.requested().then_some(args.mountpoint.as_str()),
            Self::Drives | Self::Partitions(_) | Self::Scan(_) | Self::Unmount { .. } => None,
        }
    }
}

/// Run the selected subcommand, reporting failures through the subscriber.
///
/// Returning the error from `main` would print its `Debug` form, which hides
/// the guidance the error messages carry (which partition to pick, which
/// credential is missing) behind a struct dump. It goes out as an `error!`
/// event so it lands in `--log-file` alongside everything else — and, under
/// `--json`, as one more stderr object keyed by `level`, which is why
/// nothing about a failure ever reaches stdout — except when the subscriber
/// is what failed, which nothing but stderr can report.
fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    if let Err(error) = cli::logging::init(&cli.log) {
        eprintln!("error: {error}");
        return std::process::ExitCode::FAILURE;
    }
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Dispatch the parsed command line to its handler.
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let output = cli::output::Output::new(cli.log.json);

    // `--detach`: hand the whole command to a background process and wait
    // here only until its volume is live.
    if let Some(mountpoint) = cli.command.detached_mountpoint() {
        let pid = cli::detach::spawn(mountpoint)?;
        // The background process has no console, so this is the only place
        // the volume can be announced — and the pid it carries is the one
        // holding the mount, not this process, which is about to exit.
        output.emit(&cli::output::MountedEvent::detached(mountpoint, pid));
        return Ok(());
    }

    match cli.command {
        Commands::Drives => cli::handle_drives(output),
        Commands::Partitions(args) => cli::handle_partitions(&args, output),
        Commands::Scan(args) => cli::handle_scan(&args, output),
        Commands::Mount(args) => cli::handle_mount(&args, output),
        Commands::Unmount { mountpoint } => cli::handle_unmount(&mountpoint, output),
    }
}
