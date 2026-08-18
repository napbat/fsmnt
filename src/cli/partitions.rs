//! The inspection subcommands: `drives` and `partitions`.
//!
//! One table shape for both kinds of source. A drive and an image acquired
//! from it describe the same partitions, so a listing that numbered them
//! differently — or that dropped the offset column on one of them — would
//! make the two impossible to compare. The only difference is the trailing
//! `VOLUME` column, which exists because a drive has an operating system
//! over it and an image does not.

use std::path::Path;

use fsmnt::{ImageLayout, LayoutKind, LayoutOrigin, LayoutPartition};

use super::source::{Source, resolve};
use super::{format_media_size, format_size};
use crate::PartitionsArgs;

/// List physical drives.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) fn handle_drives() -> Result<(), Box<dyn std::error::Error>> {
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

/// Physical drives cannot be enumerated on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn handle_drives() -> Result<(), Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

/// List the partitions of a drive or a disk image.
///
/// # Errors
///
/// Returns an error if the source is a directory, cannot be resolved, or
/// its layout cannot be read.
pub(crate) fn handle_partitions(args: &PartitionsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve(&args.source, args.source_kind())?;
    match &source {
        Source::Directory(path) => Err(format!(
            "{} is a directory; this command takes a disk image or a drive",
            path.display()
        )
        .into()),
        Source::Image(path) => image_partitions(args, &source, path),
        Source::Drive(drive) => drive_partitions(args, &source, drive),
    }
}

/// One line of the partition table, already formatted.
struct PartitionRow {
    /// Ordinal `--partition` takes.
    ordinal: String,
    /// GPT label, when the table stores one.
    name: Option<String>,
    /// Partition type as the table names it.
    type_name: String,
    /// Extent length, or "unknown" for a medium that would not say.
    size: String,
    /// Byte offset of the partition start.
    offset: String,
    /// Detected filesystem, or what the medium is missing of the extent.
    filesystem: String,
    /// Operating-system logical volumes over this extent; drives only.
    volume: Option<String>,
}

/// Widths of the columns whose contents decide how wide they are.
///
/// The header row is measured with the data, so a column never truncates
/// its own title, and `None` means "this table has no such column".
struct Widths {
    /// Width of `NAME`, present only for a table that stores labels.
    name: Option<usize>,
    /// Width of `TYPE`.
    type_name: usize,
    /// Width of `FILESYSTEM`, needed only when `VOLUME` follows it.
    filesystem: Option<usize>,
}

/// Everything the printer needs, whatever medium it came from.
struct Listing<'a> {
    /// The source, for the header line and the mount hint.
    source: &'a Source,
    /// Container format, for an image; drives have none.
    format: Option<String>,
    /// Length of the medium, 0 when unknown.
    size_bytes: u64,
    /// Sector size the table was read in.
    sector_size: u32,
    /// Whether that sector size was inferred rather than stated.
    sector_size_auto_detected: bool,
    /// Where the entries came from.
    origin: LayoutOrigin,
    /// The table kind, or the lack of a table.
    kind: LayoutKind,
    /// The entries themselves.
    rows: Vec<PartitionRow>,
    /// Whether a `VOLUME` column is to be printed.
    volumes: bool,
}

/// List the partitions inside a disk image.
fn image_partitions(
    args: &PartitionsArgs,
    source: &Source,
    image: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::ImageLayoutOptions;

    let mut options = ImageLayoutOptions::new();
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    if args.scan {
        options = options.with_scan(true).with_scan_stride(args.stride);
    }
    let layout: ImageLayout = fsmnt::image_layout_with_options(image, options)?;
    print_listing(&Listing {
        source,
        format: Some(layout.format.to_string()),
        size_bytes: layout.size_bytes,
        sector_size: layout.sector_size,
        sector_size_auto_detected: layout.sector_size_auto_detected,
        origin: layout.origin,
        kind: layout.kind.clone(),
        rows: layout
            .partitions
            .iter()
            .map(|partition| row(partition, None))
            .collect(),
        volumes: false,
    });
    Ok(())
}

/// List the partitions on a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn drive_partitions(
    args: &PartitionsArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::device::HostDriveEnumerator;
    use fsmnt::{DriveLayoutOptions, HostDrives};

    let mut options = DriveLayoutOptions::new();
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    if args.scan {
        options = options.with_scan(true).with_scan_stride(args.stride);
    }
    let layout = fsmnt::drive_layout::<HostDrives>(drive, options)?;
    let model = HostDrives::get_drive_info(drive)
        .ok()
        .and_then(|info| info.model);
    print_listing(&Listing {
        source,
        format: model,
        size_bytes: layout.size_bytes,
        sector_size: layout.sector_size,
        sector_size_auto_detected: layout.sector_size_auto_detected,
        origin: layout.origin,
        kind: layout.kind.clone(),
        rows: layout
            .partitions
            .iter()
            .map(|partition| row(partition, Some(logical_volumes(drive, partition))))
            .collect(),
        volumes: true,
    });
    Ok(())
}

/// Physical drives cannot be enumerated on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn drive_partitions(
    _args: &PartitionsArgs,
    _source: &Source,
    _drive: &fsmnt::device::HostDriveId,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

/// The operating-system logical volumes backed by one partition, as the
/// `VOLUME` column shows them.
///
/// A failure here is not a failure of the listing: volume discovery needs
/// privileges and services the partition table does not, and the table is
/// still worth printing without it.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn logical_volumes(drive: &fsmnt::device::HostDriveId, partition: &LayoutPartition) -> String {
    use fsmnt::HostDrives;
    use fsmnt::device::{HostVolumeResolver, PhysicalExtent};

    let extent = PhysicalExtent::new(drive.clone(), partition.offset, partition.size_bytes);
    let volumes = match HostDrives::logical_volumes(&extent) {
        Ok(volumes) => volumes,
        Err(error) => {
            tracing::debug!(
                drive = %drive,
                offset = partition.offset,
                error = %error,
                "could not resolve the logical volumes over a partition"
            );
            return "-".to_string();
        }
    };
    if volumes.is_empty() {
        return "-".to_string();
    }
    volumes
        .iter()
        .map(|volume| {
            let mounts: Vec<String> = volume
                .mount_points()
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            if mounts.is_empty() {
                volume.id().to_string()
            } else {
                format!("{} ({})", volume.id(), mounts.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Turn one layout entry into a printable row.
fn row(partition: &LayoutPartition, volume: Option<String>) -> PartitionRow {
    PartitionRow {
        // An entry with no ordinal is listed but not selectable: `-` is the
        // same placeholder `fsmnt scan` uses for a row no `--partition` can
        // name, and the TYPE column carries the command that does open it.
        ordinal: partition
            .ordinal
            .map_or_else(|| "-".to_string(), |ordinal| ordinal.to_string()),
        name: partition.name.clone(),
        type_name: partition
            .type_name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        size: format_media_size(partition.size_bytes),
        offset: partition.offset.to_string(),
        filesystem: filesystem_column(partition),
        volume,
    }
}

/// Print the header, the table, and how to mount one of its entries.
fn print_listing(listing: &Listing<'_>) {
    print_header(listing);
    match &listing.kind {
        LayoutKind::Bare(detected) => {
            println!(
                "No partition table; the whole {} is {detected:?}",
                listing.source.describe()
            );
            println!("Mount it with: fsmnt mount {} <MOUNTPOINT>", listing.source);
            return;
        }
        LayoutKind::Unknown => {
            println!(
                "Unrecognized layout: no partition table and no known filesystem at the start of \
                 the {}.",
                listing.source.describe()
            );
            return;
        }
        LayoutKind::Gpt => {
            if listing.origin == LayoutOrigin::BackupTable {
                println!(
                    "GPT partition table (recovered from the backup header in the last sector; \
                     the primary header at the front of the {} is damaged)",
                    listing.source.describe()
                );
            } else {
                println!("GPT partition table");
            }
        }
        LayoutKind::Mbr => println!("MBR partition table"),
        LayoutKind::Scanned => println!(
            "SYNTHETIC partition table — reconstructed by scanning the media every {} bytes for \
             filesystem starts. No table was read from the {}: sizes are what each filesystem \
             claims for itself, there are no names or type GUIDs, and the numbers hold only for \
             this {} scanned with this stride.",
            scan_stride(listing.origin),
            listing.source.describe(),
            listing.source.describe(),
        ),
    }

    let type_header = if matches!(listing.kind, LayoutKind::Scanned) {
        "TYPE (from scan)"
    } else {
        "TYPE"
    };
    print_table(listing, type_header);
    print_footer(listing);
}

/// The identity line: what the source is, how long, and in which sectors it
/// was read.
fn print_header(listing: &Listing<'_>) {
    let detected = if listing.sector_size_auto_detected {
        " (auto-detected)"
    } else {
        ""
    };
    let what = match (&listing.format, listing.source) {
        (Some(format), Source::Image(_)) => format!("{format} image"),
        (Some(model), _) => format!("drive ({model})"),
        (None, source) => source.describe().to_string(),
    };
    println!(
        "{}: {what}, {}, sector size {}{detected}",
        listing.source,
        format_media_size(listing.size_bytes),
        listing.sector_size,
    );
}

/// Print the column headers and every row.
///
/// The header is measured and laid out as one more row, so a column can
/// never come out narrower than its own title.
fn print_table(listing: &Listing<'_>, type_header: &str) {
    let header = PartitionRow {
        ordinal: "#".to_string(),
        name: Some("NAME".to_string()),
        type_name: type_header.to_string(),
        size: "SIZE".to_string(),
        offset: "OFFSET".to_string(),
        filesystem: "FILESYSTEM".to_string(),
        volume: Some("VOLUME".to_string()),
    };
    let measured = || std::iter::once(&header).chain(&listing.rows);
    let widths = Widths {
        name: listing
            .rows
            .iter()
            .any(|row| row.name.is_some())
            .then(|| column_width(measured().map(|row| row.name.as_deref()))),
        type_name: column_width(measured().map(|row| Some(row.type_name.as_str()))),
        // Only the last column is left unpadded, so FILESYSTEM needs a width
        // whenever VOLUME follows it.
        filesystem: listing
            .volumes
            .then(|| column_width(measured().map(|row| Some(row.filesystem.as_str())))),
    };

    println!("{}", format_row(&header, &widths));
    for row in &listing.rows {
        println!("{}", format_row(row, &widths));
    }
}

/// Lay one row out across the columns this table has.
fn format_row(row: &PartitionRow, widths: &Widths) -> String {
    let name = match widths.name {
        Some(width) => format!("  {:<width$}", row.name.as_deref().unwrap_or("-")),
        None => String::new(),
    };
    let tail = match widths.filesystem {
        Some(width) => format!(
            "  {:<width$}  {}",
            row.filesystem,
            row.volume.as_deref().unwrap_or("-")
        ),
        None => format!("  {}", row.filesystem),
    };
    let type_width = widths.type_name;
    format!(
        "{:>4}{name}  {:<type_width$} {:>12} {:>14}{tail}",
        row.ordinal, row.type_name, row.size, row.offset
    )
}

/// How to mount one of the entries just listed.
fn print_footer(listing: &Listing<'_>) {
    let synthetic = matches!(listing.kind, LayoutKind::Scanned);
    if listing.rows.is_empty() {
        if synthetic {
            let stride = scan_stride(listing.origin);
            println!(
                "(the scan found no filesystems; a start off a {stride}-byte boundary needs \
                 --stride 512)"
            );
        } else {
            println!("(no non-empty partition entries)");
        }
        return;
    }
    if synthetic {
        println!(
            "\nMount one with: fsmnt mount {} <MOUNTPOINT> --scan{} --partition <#>   (synthetic \
             numbering — from this scan, not from the {})",
            listing.source,
            stride_flag(scan_stride(listing.origin)),
            listing.source.describe(),
        );
    } else {
        println!(
            "\nMount one with: fsmnt mount {} <MOUNTPOINT> --partition <#>",
            listing.source
        );
    }
}

/// The stride a scanned layout was built with.
fn scan_stride(origin: LayoutOrigin) -> u64 {
    match origin {
        LayoutOrigin::Scan { stride } => stride,
        LayoutOrigin::Table | LayoutOrigin::BackupTable | LayoutOrigin::None => {
            fsmnt::DEFAULT_STRIDE
        }
    }
}

/// The `--stride` a hint has to repeat, or nothing when it is the default.
fn stride_flag(stride: u64) -> String {
    if stride == fsmnt::DEFAULT_STRIDE {
        String::new()
    } else {
        format!(" --stride {stride}")
    }
}

/// Width of a column: the longest value any row puts in it, counting the
/// placeholder an absent value is printed as.
fn column_width<'a>(values: impl Iterator<Item = Option<&'a str>>) -> usize {
    values
        .map(|value| value.unwrap_or("-").len())
        .max()
        .unwrap_or(0)
}

/// Column text for a partition's detected filesystem.
fn detected_label(detected: Option<fsmnt::device::DetectedBootSector>) -> String {
    detected.map_or_else(|| "unreadable".to_string(), |d| format!("{d:?}"))
}

/// Column text for a partition: what it holds, and how much of it the medium
/// is missing.
///
/// A partition table describes the drive it was written on, not the file
/// that was captured from it. Saying "unreadable" for an extent the
/// acquisition never reached invites a hunt for corruption; saying it is
/// past the end of the medium says what happened.
fn filesystem_column(partition: &LayoutPartition) -> String {
    // A declared length of 0 means "unknown, running to the end of the
    // medium", not an extent the medium stops short of.
    if partition.size_bytes > 0 && partition.is_beyond_end() {
        return "beyond end of media".to_string();
    }
    let detected = detected_label(partition.detected);
    if partition.is_truncated() {
        return format!(
            "{detected}  TRUNCATED ({} missing)",
            format_size(partition.missing_bytes)
        );
    }
    detected
}
