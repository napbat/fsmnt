//! The `scan` subcommand: look for filesystems anywhere in an image.

use std::path::Path;

use fsmnt::{ScanHit, ScanHitKind, ScanOptions};

use super::format_size;
use super::size::DEFAULT_SECTOR_SIZE;

/// Everything `scan` needs.
pub(crate) struct ScanImageOptions<'a> {
    /// Image path, or the first segment of an EWF set.
    pub(crate) image: &'a Path,
    /// Distance between candidate positions, in bytes.
    pub(crate) stride: u64,
    /// Sector size the offset column is also reported in.
    pub(crate) sector_size: Option<u32>,
}

/// Scan an image for filesystem starts and print the candidate offsets.
pub(crate) fn handle_scan(
    options: &ScanImageOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let image = options.image;
    let sector_size = options.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE);
    let reader = fsmnt::ImageReader::open(image)?;
    println!(
        "{}: {} image, {}",
        image.display(),
        reader.format(),
        format_size(reader.len()),
    );
    println!(
        "Scanning every {} bytes for filesystem starts...",
        options.stride
    );
    drop(reader);

    let hits =
        fsmnt::scan_image_with_options(image, ScanOptions::new().with_stride(options.stride))?;
    if hits.is_empty() {
        println!(
            "\nNo filesystems found. A filesystem whose start is not aligned to {} bytes needs \
             a finer scan: --stride 512.",
            options.stride
        );
        return Ok(());
    }

    // The `#` column is the SYNTHETIC ordinal `mount-image --scan --partition`
    // takes: the position among mountable hits, in scan order — the same
    // numbering `partitions --scan` prints. It exists only for this image at
    // this stride; partition tables get no number because they are not
    // mountable.
    println!(
        "\n{:>4}  {:>14} {:>14}  {:<22} {:>12}  NOTE",
        "#", "OFFSET", "SECTOR", "TYPE", "SIZE"
    );
    let mut ordinal = 0_usize;
    for hit in &hits {
        let number = if hit.mount_offset().is_some() {
            let shown = ordinal.to_string();
            ordinal += 1;
            shown
        } else {
            "-".to_string()
        };
        println!(
            "{number:>4}  {:>14} {:>14}  {:<22} {:>12}  {}",
            hit.offset,
            sector_column(hit.offset, sector_size),
            type_column(hit),
            hit.size_bytes.map_or_else(|| "-".to_string(), format_size),
            note_column(hit),
        );
    }

    if let Some(first) = hits.iter().find(|hit| hit.mount_offset().is_some()) {
        let offset = first.mount_offset().unwrap_or(first.offset);
        let stride_flag = if options.stride == fsmnt::DEFAULT_STRIDE {
            String::new()
        } else {
            format!(" --stride {}", options.stride)
        };
        println!(
            "\nMount one with: fsmnt mount-image {0} <MOUNTPOINT> --offset {offset}\n\
             or by its # above:  fsmnt mount-image {0} <MOUNTPOINT> --scan{stride_flag} \
             --partition <#>   (# is synthetic — from this scan, not from the image)",
            image.display(),
        );
    }
    Ok(())
}

/// The offset expressed in sectors, or `-` when it is not a whole number of
/// them.
fn sector_column(offset: u64, sector_size: u32) -> String {
    let sector_size = u64::from(sector_size);
    if sector_size == 0 || !offset.is_multiple_of(sector_size) {
        return "-".to_string();
    }
    format!("{}s", offset / sector_size)
}

/// The type column: the detected filesystem, or what a lone superblock is.
fn type_column(hit: &ScanHit) -> String {
    match hit.kind {
        ScanHitKind::Filesystem(detected) | ScanHitKind::PartitionTable(detected) => {
            format!("{detected:?}")
        }
        ScanHitKind::ExtBackupSuperblock { .. } => "Ext (backup only)".to_string(),
    }
}

/// The note column: what the hit is evidence of.
fn note_column(hit: &ScanHit) -> String {
    match hit.kind {
        ScanHitKind::PartitionTable(_) => {
            "partition table; list it with `fsmnt partitions`".to_string()
        }
        ScanHitKind::ExtBackupSuperblock {
            group,
            filesystem_start,
        } => match filesystem_start {
            Some(start) => {
                format!("backup superblock of group {group}; filesystem start would be at {start}")
            }
            None => format!(
                "backup superblock of group {group}; its filesystem starts before this image"
            ),
        },
        ScanHitKind::Filesystem(_) => backups_note(hit),
    }
}

/// How many backup superblocks corroborate a filesystem hit, and from which
/// block groups.
fn backups_note(hit: &ScanHit) -> String {
    if hit.backup_superblocks.is_empty() {
        return String::new();
    }
    let groups: Vec<String> = hit
        .backup_superblocks
        .iter()
        .map(|backup| backup.group.to_string())
        .collect();
    let count = hit.backup_superblocks.len();
    let plural = if count == 1 { "" } else { "s" };
    format!(
        "{count} backup superblock{plural} (group{plural} {})",
        groups.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::{backups_note, sector_column, type_column};
    use fsmnt::device::DetectedBootSector;
    use fsmnt::{ExtBackupSuperblock, ScanHit, ScanHitKind};

    fn ext_hit(offset: u64, backups: &[(u64, u16)]) -> ScanHit {
        ScanHit {
            offset,
            kind: ScanHitKind::Filesystem(DetectedBootSector::Ext),
            size_bytes: Some(4096),
            backup_superblocks: backups
                .iter()
                .map(|&(offset, group)| ExtBackupSuperblock { offset, group })
                .collect(),
        }
    }

    #[test]
    fn offsets_are_also_shown_in_sectors_when_they_divide_evenly() {
        assert_eq!(sector_column(270_532_608, 512), "528384s");
        assert_eq!(sector_column(0, 512), "0s");
        assert_eq!(sector_column(270_533_632, 4096), "-");
    }

    #[test]
    fn folded_backups_are_summarized_by_group() {
        assert_eq!(backups_note(&ext_hit(0, &[])), "");
        assert_eq!(
            backups_note(&ext_hit(0, &[(1024, 1)])),
            "1 backup superblock (group 1)"
        );
        assert_eq!(
            backups_note(&ext_hit(0, &[(1024, 1), (2048, 3), (4096, 9)])),
            "3 backup superblocks (groups 1, 3, 9)"
        );
    }

    #[test]
    fn only_filesystems_and_implied_starts_are_mountable() {
        assert_eq!(ext_hit(512, &[]).mount_offset(), Some(512));
        let table = ScanHit {
            offset: 0,
            kind: ScanHitKind::PartitionTable(DetectedBootSector::GptPartitioned),
            size_bytes: None,
            backup_superblocks: Vec::new(),
        };
        assert_eq!(table.mount_offset(), None);
        assert_eq!(type_column(&table), "GptPartitioned");

        let orphan = ScanHit {
            offset: 8192,
            kind: ScanHitKind::ExtBackupSuperblock {
                group: 3,
                filesystem_start: Some(1024),
            },
            size_bytes: None,
            backup_superblocks: Vec::new(),
        };
        assert_eq!(
            orphan.mount_offset(),
            Some(1024),
            "a lone backup points at where its filesystem began, not at itself"
        );
        assert_eq!(type_column(&orphan), "Ext (backup only)");
    }
}
