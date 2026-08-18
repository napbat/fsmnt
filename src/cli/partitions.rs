//! The inspection subcommands: `drives` and `partitions`.

use std::path::Path;

use super::format_size;

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

/// List the partitions of a drive ID or a disk image.
///
/// The positional argument is overloaded, so decide which it is before
/// touching either backend; see [`is_image_target`].
pub(crate) fn handle_partitions(
    target: &str,
    sector_size: Option<u32>,
    scan_stride: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_image_target(target) {
        image_partitions(Path::new(target), sector_size, scan_stride)
    } else if scan_stride.is_some() {
        Err(format!(
            "--scan reconstructs a table from an image file; {target} is a drive ID — image the \
             drive first, or use `fsmnt scan` on an image"
        )
        .into())
    } else {
        drive_partitions(target, sector_size)
    }
}

/// Whether `target` names an image file rather than a physical drive.
///
/// Drive IDs are bare tokens (`0`, `sda`, `disk2`, `nvme0n1`): they never
/// contain a path separator and never have a file extension, so anything
/// that does — or that already exists as a file — is an image path.
pub(super) fn is_image_target(target: &str) -> bool {
    let path = Path::new(target);
    path.is_file() || target.contains(['/', '\\']) || path.extension().is_some()
}

/// List the partitions inside a disk image.
fn image_partitions(
    image: &Path,
    sector_size: Option<u32>,
    scan_stride: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::{ImageLayoutKind, ImageLayoutOptions, LayoutOrigin};

    let mut options = ImageLayoutOptions::new();
    if let Some(sector_size) = sector_size {
        options = options.with_sector_size(sector_size);
    }
    if let Some(stride) = scan_stride {
        options = options.with_scan(true).with_scan_stride(stride);
    }
    let layout = fsmnt::image_layout_with_options(image, options)?;
    let detected_note = if layout.sector_size_auto_detected {
        " (auto-detected)"
    } else {
        ""
    };
    println!(
        "{}: {} image, {}, sector size {}{detected_note}",
        image.display(),
        layout.format,
        format_size(layout.size_bytes),
        layout.sector_size,
    );

    match layout.kind {
        ImageLayoutKind::Scanned => {
            print_scanned_layout(image, &layout);
            return Ok(());
        }
        ImageLayoutKind::Gpt => {
            if layout.origin == LayoutOrigin::BackupTable {
                println!(
                    "GPT partition table (recovered from the backup header in the last sector; \
                     the primary header at the front of the image is damaged)"
                );
            } else {
                println!("GPT partition table");
            }
            println!(
                "{:>4}  {:<24} {:<22} {:>12} {:>14}  FILESYSTEM",
                "#", "NAME", "TYPE", "SIZE", "OFFSET"
            );
            for partition in &layout.partitions {
                println!(
                    "{:>4}  {:<24} {:<22} {:>12} {:>14}  {}",
                    partition.ordinal,
                    partition.name.as_deref().unwrap_or("-"),
                    partition.type_name.as_deref().unwrap_or("Unknown"),
                    format_size(partition.size_bytes),
                    partition.offset,
                    filesystem_column(partition),
                );
            }
        }
        ImageLayoutKind::Mbr => {
            println!("MBR partition table");
            println!(
                "{:>4}  {:<22} {:>12} {:>14}  FILESYSTEM",
                "#", "TYPE", "SIZE", "OFFSET"
            );
            for partition in &layout.partitions {
                println!(
                    "{:>4}  {:<22} {:>12} {:>14}  {}",
                    partition.ordinal,
                    partition.type_name.as_deref().unwrap_or("Unknown"),
                    format_size(partition.size_bytes),
                    partition.offset,
                    filesystem_column(partition),
                );
            }
        }
        ImageLayoutKind::Bare(detected) => {
            println!("No partition table; the whole image is {detected:?}");
            println!(
                "Mount it with: fsmnt mount-image {} <MOUNTPOINT>",
                image.display()
            );
            return Ok(());
        }
        ImageLayoutKind::Unknown => {
            println!("Unrecognized image layout: no partition table and no known filesystem.");
            return Ok(());
        }
    }

    if layout.partitions.is_empty() {
        println!("(no non-empty partition entries)");
    } else {
        println!(
            "\nMount one with: fsmnt mount-image {} <MOUNTPOINT> --partition <#>",
            image.display()
        );
    }
    Ok(())
}

/// Print a layout reconstructed from a scan, saying loudly that it is
/// synthetic: nothing about it was read from a partition table.
fn print_scanned_layout(image: &Path, layout: &fsmnt::ImageLayout) {
    use fsmnt::LayoutOrigin;

    let stride = match layout.origin {
        LayoutOrigin::Scan { stride } => stride,
        _ => fsmnt::DEFAULT_STRIDE,
    };
    println!(
        "SYNTHETIC partition table — reconstructed by scanning the media every {stride} \
         bytes for filesystem starts. No table was read from the image: sizes are what \
         each filesystem claims for itself, there are no names or type GUIDs, and the \
         numbers hold only for this image scanned with this stride."
    );
    println!(
        "{:>4}  {:<40} {:>12} {:>14}  FILESYSTEM",
        "#", "TYPE (from scan)", "SIZE", "OFFSET"
    );
    for partition in &layout.partitions {
        println!(
            "{:>4}  {:<40} {:>12} {:>14}  {}",
            partition.ordinal,
            partition.type_name.as_deref().unwrap_or("Unknown"),
            format_size(partition.size_bytes),
            partition.offset,
            filesystem_column(partition),
        );
    }
    if layout.partitions.is_empty() {
        println!(
            "(the scan found no filesystems; a start off a {stride}-byte boundary needs --stride 512)"
        );
    } else {
        let stride_flag = if stride == fsmnt::DEFAULT_STRIDE {
            String::new()
        } else {
            format!(" --stride {stride}")
        };
        println!(
            "\nMount one with: fsmnt mount-image {} <MOUNTPOINT> --scan{stride_flag} \
             --partition <#>   (synthetic numbering — from this scan, not from the image)",
            image.display()
        );
    }
}

/// Column text for a partition's detected filesystem.
fn detected_label(detected: Option<fsmnt::device::DetectedBootSector>) -> String {
    detected.map_or_else(|| "unreadable".to_string(), |d| format!("{d:?}"))
}

/// Column text for an image partition: what it holds, and how much of it the
/// image is missing.
///
/// A partition table describes the drive it was written on, not the file
/// that was captured from it. Saying "unreadable" for an extent the
/// acquisition never reached invites a hunt for corruption; saying it is
/// past the end of the image says what happened.
fn filesystem_column(partition: &fsmnt::ImagePartition) -> String {
    if partition.is_beyond_end() {
        return "beyond end of image".to_string();
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

/// List the partitions on a physical drive.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn drive_partitions(
    drive: &str,
    requested_sector_size: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::{Disk, DiskLayout, HostDriveEnumerator, HostDriveId};

    let id = HostDriveId::new(drive);
    let info = HostDrives::get_drive_info(&id).ok();
    let sector_size = requested_sector_size
        .or_else(|| info.as_ref().and_then(|i| i.sector_size))
        .unwrap_or(super::size::DEFAULT_SECTOR_SIZE);
    let reader = HostDrives::open_drive(&id)?;
    let mut disk = Disk::with_sector_size(reader, sector_size)?;
    let sector = disk.sector_size();

    match disk.layout().clone() {
        DiskLayout::Gpt {
            header,
            from_backup,
        } => {
            if from_backup {
                println!(
                    "GPT disk (sector size {sector}; table recovered from the backup header in \
                     the last sector — the primary at LBA 1 is damaged)"
                );
            } else {
                println!("GPT disk (sector size {sector})");
            }
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
                    detected_label(detected),
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
                    detected_label(detected),
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

/// Physical drives cannot be enumerated on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn drive_partitions(
    drive: &str,
    _requested_sector_size: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!(
        "'{drive}' is not an image file, and physical drives cannot be enumerated on this platform"
    )
    .into())
}
