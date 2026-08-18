//! The inspection subcommands: `drives` and `partitions`.
//!
//! One table shape for both kinds of source. A drive and an image acquired
//! from it describe the same partitions, so a listing that numbered them
//! differently — or that dropped the offset column on one of them — would
//! make the two impossible to compare. The only difference is the trailing
//! `VOLUME` column, which exists because a drive has an operating system
//! over it and an image does not.
//!
//! Each handler reads the medium once into a typed report
//! ([`PartitionsDocument`], [`DrivesDocument`]) and emits it; the table
//! below is that report's own human rendering, laid out over the same
//! numbers a program receives, so the two can never disagree about what was
//! found.

use std::io::Write;
use std::path::Path;

use fsmnt::{LayoutKind, LayoutOrigin, LayoutPartition};

use super::output::{
    DriveEntry, DrivesDocument, Output, PartitionEntry, PartitionsDocument, Report, Shape,
    VolumeEntry,
};
use super::source::{Source, resolve};
use super::{format_media_size, format_size};
use crate::PartitionsArgs;

/// List physical drives.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) fn handle_drives(output: Output) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::HostDriveEnumerator;

    output.emit(&DrivesDocument::new(&HostDrives::enumerate_drives()?));
    Ok(())
}

/// Physical drives cannot be enumerated on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn handle_drives(_output: Output) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

impl Report for DrivesDocument {
    const SHAPE: Shape = Shape::Document;

    /// One line per drive, and for every one this process cannot read, the
    /// reason in the `ACCESS` column rather than an omission.
    fn render_text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        if self.drives.is_empty() {
            return writeln!(out, "No drives found.");
        }

        writeln!(
            out,
            "{:<10} {:>12}  {:<10} {:<28} ACCESS",
            "ID", "SIZE", "BUS", "MODEL"
        )?;
        for drive in &self.drives {
            writeln!(out, "{}", drive_row(drive))?;
        }
        Ok(())
    }
}

/// One line of the drive table.
fn drive_row(drive: &DriveEntry) -> String {
    let size = drive
        .size_bytes
        .map_or_else(|| "unknown".to_string(), format_size);
    let bus = drive
        .bus
        .map_or_else(|| "-".to_string(), |bus| bus.to_string());
    let model = drive.model.as_deref().unwrap_or("-");
    let access = if drive.accessible {
        "ok".to_string()
    } else {
        format!(
            "inaccessible ({})",
            drive.access_error.as_deref().unwrap_or("unknown"),
        )
    };
    format!(
        "{:<10} {size:>12}  {bus:<10} {model:<28} {access}",
        drive.id
    )
}

/// List the partitions of a drive or a disk image.
///
/// # Errors
///
/// Returns an error if the source is a directory, cannot be resolved, or
/// its layout cannot be read.
pub(crate) fn handle_partitions(
    args: &PartitionsArgs,
    output: Output,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve(&args.source, args.source_kind())?;
    let document = match &source {
        Source::Directory(path) => {
            return Err(format!(
                "{} is a directory; this command takes a disk image or a drive",
                path.display()
            )
            .into());
        }
        Source::Image(path) => image_partitions(args, &source, path)?,
        Source::Drive(drive) => drive_partitions(args, &source, drive)?,
    };
    output.emit(&document);
    Ok(())
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

/// Enumerate the partitions inside a disk image.
fn image_partitions(
    args: &PartitionsArgs,
    source: &Source,
    image: &Path,
) -> Result<PartitionsDocument, Box<dyn std::error::Error>> {
    use fsmnt::ImageLayoutOptions;

    let mut options = ImageLayoutOptions::new();
    if let Some(sector_size) = args.sector_size {
        options = options.with_sector_size(sector_size);
    }
    if args.scan {
        options = options.with_scan(true).with_scan_stride(args.stride);
    }
    let layout = fsmnt::image_layout_with_options(image, options)?;
    Ok(PartitionsDocument::from_image(source, &layout))
}

/// Enumerate the partitions on a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn drive_partitions(
    args: &PartitionsArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<PartitionsDocument, Box<dyn std::error::Error>> {
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
    Ok(PartitionsDocument::from_drive(
        source,
        model,
        &layout,
        |partition| logical_volumes(drive, partition),
    ))
}

/// Physical drives cannot be enumerated on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn drive_partitions(
    _args: &PartitionsArgs,
    _source: &Source,
    _drive: &fsmnt::device::HostDriveId,
) -> Result<PartitionsDocument, Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

/// The operating-system logical volumes backed by one partition.
///
/// A failure here is not a failure of the listing: volume discovery needs
/// privileges and services the partition table does not, and the table is
/// still worth printing without it. That is why it is `None` rather than an
/// empty list — "nobody could look" and "nothing is there" are different
/// answers, and the JSON keeps them apart.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn logical_volumes(
    drive: &fsmnt::device::HostDriveId,
    partition: &LayoutPartition,
) -> Option<Vec<VolumeEntry>> {
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
            return None;
        }
    };
    Some(
        volumes
            .iter()
            .map(|volume| VolumeEntry {
                id: volume.id().to_string(),
                mount_points: volume
                    .mount_points()
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            })
            .collect(),
    )
}

/// Turn one listed entry into a printable row.
fn row(partition: &PartitionEntry) -> PartitionRow {
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
        size: format_media_size(partition.size_bytes.unwrap_or_default()),
        offset: partition.offset.to_string(),
        filesystem: filesystem_column(partition),
        volume: partition
            .volumes
            .as_ref()
            .map(|volumes| volume_column(volumes)),
    }
}

impl Report for PartitionsDocument {
    const SHAPE: Shape = Shape::Document;

    /// The header, the table, and how to mount one of its entries.
    fn render_text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let source = &self.source;
        write_header(out, self)?;
        match &self.table {
            LayoutKind::Bare(detected) => {
                writeln!(
                    out,
                    "No partition table; the whole {} is {detected:?}",
                    source.describe()
                )?;
                return writeln!(
                    out,
                    "Mount it with: fsmnt mount {} <MOUNTPOINT>",
                    source.name()
                );
            }
            LayoutKind::Unknown => {
                return writeln!(
                    out,
                    "Unrecognized layout: no partition table and no known filesystem at the start \
                     of the {}.",
                    source.describe()
                );
            }
            LayoutKind::Gpt => {
                if self.origin == LayoutOrigin::BackupTable {
                    writeln!(
                        out,
                        "GPT partition table (recovered from the backup header in the last \
                         sector; the primary header at the front of the {} is damaged)",
                        source.describe()
                    )?;
                } else {
                    writeln!(out, "GPT partition table")?;
                }
            }
            LayoutKind::Mbr => writeln!(out, "MBR partition table")?,
            LayoutKind::Scanned => writeln!(
                out,
                "SYNTHETIC partition table — reconstructed by scanning the media every {} bytes \
                 for filesystem starts. No table was read from the {}: sizes are what each \
                 filesystem claims for itself, there are no names or type GUIDs, and the numbers \
                 hold only for this {} scanned with this stride.",
                scan_stride(self),
                source.describe(),
                source.describe(),
            )?,
        }

        let type_header = if matches!(self.table, LayoutKind::Scanned) {
            "TYPE (from scan)"
        } else {
            "TYPE"
        };
        write_table(out, self, type_header)?;
        write_footer(out, self)
    }
}

/// The identity line: what the source is, how long, and in which sectors it
/// was read.
fn write_header(out: &mut dyn Write, listing: &PartitionsDocument) -> std::io::Result<()> {
    let detected = if listing.sector_size_auto_detected {
        " (auto-detected)"
    } else {
        ""
    };
    let what = match (listing.format, listing.model.as_deref()) {
        (Some(format), _) => format!("{format} image"),
        (None, Some(model)) => format!("drive ({model})"),
        (None, None) => listing.source.describe().to_string(),
    };
    writeln!(
        out,
        "{}: {what}, {}, sector size {}{detected}",
        listing.source.name(),
        format_media_size(listing.size_bytes.unwrap_or_default()),
        listing.sector_size,
    )
}

/// Write the column headers and every row.
///
/// The header is measured and laid out as one more row, so a column can
/// never come out narrower than its own title.
fn write_table(
    out: &mut dyn Write,
    listing: &PartitionsDocument,
    type_header: &str,
) -> std::io::Result<()> {
    let header = PartitionRow {
        ordinal: "#".to_string(),
        name: Some("NAME".to_string()),
        type_name: type_header.to_string(),
        size: "SIZE".to_string(),
        offset: "OFFSET".to_string(),
        filesystem: "FILESYSTEM".to_string(),
        volume: Some("VOLUME".to_string()),
    };
    let rows: Vec<PartitionRow> = listing.partitions.iter().map(row).collect();
    let measured = || std::iter::once(&header).chain(&rows);
    let widths = Widths {
        name: rows
            .iter()
            .any(|row| row.name.is_some())
            .then(|| column_width(measured().map(|row| row.name.as_deref()))),
        type_name: column_width(measured().map(|row| Some(row.type_name.as_str()))),
        // Only the last column is left unpadded, so FILESYSTEM needs a width
        // whenever VOLUME follows it.
        filesystem: listing
            .source
            .is_drive()
            .then(|| column_width(measured().map(|row| Some(row.filesystem.as_str())))),
    };

    writeln!(out, "{}", format_row(&header, &widths))?;
    for row in &rows {
        writeln!(out, "{}", format_row(row, &widths))?;
    }
    Ok(())
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
fn write_footer(out: &mut dyn Write, listing: &PartitionsDocument) -> std::io::Result<()> {
    let source = listing.source.name();
    let synthetic = matches!(listing.table, LayoutKind::Scanned);
    if listing.partitions.is_empty() {
        if synthetic {
            let stride = scan_stride(listing);
            return writeln!(
                out,
                "(the scan found no filesystems; a start off a {stride}-byte boundary needs \
                 --stride 512)"
            );
        }
        return writeln!(out, "(no non-empty partition entries)");
    }
    if synthetic {
        writeln!(
            out,
            "\nMount one with: fsmnt mount {source} <MOUNTPOINT> --scan{} --partition <#>   \
             (synthetic numbering — from this scan, not from the {})",
            stride_flag(scan_stride(listing)),
            listing.source.describe(),
        )
    } else {
        writeln!(
            out,
            "\nMount one with: fsmnt mount {source} <MOUNTPOINT> --partition <#>"
        )
    }
}

/// The stride a scanned layout was built with.
fn scan_stride(listing: &PartitionsDocument) -> u64 {
    listing.scan_stride.unwrap_or(fsmnt::DEFAULT_STRIDE)
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
fn filesystem_column(partition: &PartitionEntry) -> String {
    if partition.beyond_end {
        return "beyond end of media".to_string();
    }
    let detected = detected_label(partition.filesystem);
    if partition.truncated {
        return format!(
            "{detected}  TRUNCATED ({} missing)",
            format_size(partition.missing_bytes)
        );
    }
    detected
}

/// Column text for the operating-system volumes over a partition.
fn volume_column(volumes: &[VolumeEntry]) -> String {
    if volumes.is_empty() {
        return "-".to_string();
    }
    volumes
        .iter()
        .map(|volume| {
            if volume.mount_points.is_empty() {
                volume.id.clone()
            } else {
                format!("{} ({})", volume.id, volume.mount_points.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
