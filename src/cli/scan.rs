//! The `scan` subcommand: look for filesystems anywhere in a medium.
//!
//! A drive whose partition table was wiped and an image of one are the same
//! forensic situation, so both are searched the same way and produce the
//! same table; only the identity line at the top differs, because an image
//! has a container format and a drive has a model.

use fsmnt::{ScanHit, ScanHitKind, ScanOptions};

use super::format_media_size;
use super::size::DEFAULT_SECTOR_SIZE;
use super::source::{Source, resolve};
use crate::ScanArgs;

/// Search a drive or a disk image for filesystem starts and print the
/// candidate offsets.
///
/// # Errors
///
/// Returns an error if the source is a directory, cannot be resolved, or
/// cannot be read to the end.
pub(crate) fn handle_scan(args: &ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve(&args.source, args.source_kind())?;
    let hits = match &source {
        Source::Directory(path) => {
            return Err(format!(
                "{} is a directory; this command takes a disk image or a drive",
                path.display()
            )
            .into());
        }
        Source::Image(path) => {
            let reader = fsmnt::ImageReader::open(path)?;
            println!(
                "{}: {} image, {}",
                path.display(),
                reader.format(),
                format_media_size(reader.len()),
            );
            drop(reader);
            tracing::info!(
                "scanning {source} every {} bytes for filesystem starts",
                args.stride
            );
            fsmnt::scan_image_with_options(path, ScanOptions::new().with_stride(args.stride))?
        }
        Source::Drive(drive) => scan_drive(args, &source, drive)?,
    };

    print_hits(args, &source, &hits);
    Ok(())
}

/// Scan a physical drive, announcing it the way an image announces itself.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn scan_drive(
    args: &ScanArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<Vec<ScanHit>, Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::HostDriveEnumerator;

    let info = HostDrives::get_drive_info(drive).ok();
    let model = info
        .as_ref()
        .and_then(|info| info.model.as_deref())
        .unwrap_or("unknown model");
    let size = info
        .as_ref()
        .and_then(|info| info.size_bytes)
        .map_or_else(|| "unknown".to_string(), format_media_size);
    println!("{drive}: drive ({model}), {size}");
    tracing::info!(
        "scanning {source} every {} bytes for filesystem starts",
        args.stride
    );
    Ok(fsmnt::scan_drive::<HostDrives>(
        drive,
        ScanOptions::new().with_stride(args.stride),
    )?)
}

/// Physical drives cannot be scanned on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn scan_drive(
    _args: &ScanArgs,
    _source: &Source,
    _drive: &fsmnt::device::HostDriveId,
) -> Result<Vec<ScanHit>, Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

/// Print what the scan found, and the two ways to mount one of them.
fn print_hits(args: &ScanArgs, source: &Source, hits: &[ScanHit]) {
    let sector_size = args.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE);
    if hits.is_empty() {
        println!(
            "\nNo filesystems found. A filesystem whose start is not aligned to {} bytes needs a \
             finer scan: --stride 512.",
            args.stride
        );
        return;
    }

    // The `#` column is the SYNTHETIC ordinal `fsmnt mount --scan
    // --partition` takes: the position among mountable hits, in scan order —
    // the same numbering `partitions --scan` prints. It exists only for this
    // medium at this stride; partition tables get no number because they are
    // not mountable.
    println!(
        "\n{:>4}  {:>14} {:>14}  {:<22} {:>12}  NOTE",
        "#", "OFFSET", "SECTOR", "TYPE", "SIZE"
    );
    let mut ordinal = 0_usize;
    for hit in hits {
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
            hit.size_bytes
                .map_or_else(|| "-".to_string(), format_media_size),
            note_column(hit),
        );
    }

    let Some(first) = hits.iter().find(|hit| hit.mount_offset().is_some()) else {
        // Every row above is evidence *about* a filesystem rather than the
        // start of one, so there is no offset to offer. Saying that is more
        // use than a mount command with nothing to put in it.
        println!(
            "\nNothing found is mountable: no row above is the start of a filesystem. A start \
             that is not aligned to {} bytes needs a finer scan: --stride 512.",
            args.stride
        );
        return;
    };
    let offset = first.mount_offset().unwrap_or(first.offset);
    let stride_flag = if args.stride == fsmnt::DEFAULT_STRIDE {
        String::new()
    } else {
        format!(" --stride {}", args.stride)
    };
    println!(
        "\nMount one with: fsmnt mount {source} <MOUNTPOINT> --offset {offset}\n\
         or by its # above:  fsmnt mount {source} <MOUNTPOINT> --scan{stride_flag} \
         --partition <#>   (# is synthetic — from this scan, not from the {})",
        source.describe(),
    );
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
        // Copies of a primary that nothing corroborates are just copies;
        // once a backup names the offset as a start, the same bytes become a
        // filesystem whose descriptor table is broken.
        ScanHitKind::ExtPrimaryCopies { .. } => if hit.mount_offset().is_some() {
            "Ext (table damaged)"
        } else {
            "Ext (superblock copies)"
        }
        .to_string(),
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
            start_before_medium,
        } => orphan_backup_note(hit, group, filesystem_start, start_before_medium),
        ScanHitKind::ExtPrimaryCopies {
            copies,
            last_offset,
        } => primary_copies_note(hit, copies, last_offset),
        ScanHitKind::Filesystem(_) => backups_note(hit),
    }
}

/// What a backup superblock with no primary says, and which of its siblings
/// agree with it.
fn orphan_backup_note(
    hit: &ScanHit,
    group: u16,
    filesystem_start: Option<u64>,
    start_before_medium: Option<u64>,
) -> String {
    use std::fmt::Write as _;

    let mut note = format!("backup superblock of group {group}");
    if !hit.backup_superblocks.is_empty() {
        let plural = if hit.backup_superblocks.len() == 1 {
            ""
        } else {
            "s"
        };
        // Writing into a `String` cannot fail, so the result is discarded
        // the way `write!` to a formatter would be.
        let _ = write!(note, ", corroborated by group{plural} {}", group_list(hit));
    }
    let _ = match (filesystem_start, start_before_medium) {
        (Some(start), _) => write!(note, "; filesystem start would be at {start}"),
        (None, Some(before)) => write!(
            note,
            "; the filesystem starts {before} bytes before this medium — the image begins inside it"
        ),
        (None, None) => write!(note, "; its filesystem starts before this medium"),
    };
    note
}

/// What a run of unconfirmed primary superblocks says.
fn primary_copies_note(hit: &ScanHit, copies: usize, last_offset: u64) -> String {
    if hit.mount_offset().is_some() {
        let groups = group_list(hit);
        let group = hit
            .backup_superblocks
            .first()
            .map_or(0, |backup| backup.group);
        let plural = if hit.backup_superblocks.len() == 1 {
            ""
        } else {
            "s"
        };
        return format!(
            "primary superblock whose descriptor table does not verify, but backups at \
             group{plural} {groups} name this offset as the start; mount with --offset {} \
             --backup-superblock {group}",
            hit.offset,
        );
    }
    if copies == 1 {
        return format!(
            "one copy of a primary superblock at {}, not followed by its group descriptors — a \
             journal write inside a filesystem, not a start",
            hit.offset,
        );
    }
    format!(
        "{copies} copies of a primary superblock between {} and {last_offset}, none followed by \
         its group descriptors — journal writes inside a filesystem, not a start",
        hit.offset,
    )
}

/// How many backup superblocks corroborate a filesystem hit, and from which
/// block groups.
fn backups_note(hit: &ScanHit) -> String {
    if hit.backup_superblocks.is_empty() {
        return String::new();
    }
    let count = hit.backup_superblocks.len();
    let plural = if count == 1 { "" } else { "s" };
    format!(
        "{count} backup superblock{plural} (group{plural} {})",
        group_list(hit)
    )
}

/// The block groups of a hit's folded backup superblocks, comma-separated.
fn group_list(hit: &ScanHit) -> String {
    hit.backup_superblocks
        .iter()
        .map(|backup| backup.group.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{backups_note, note_column, sector_column, type_column};
    use fsmnt::device::DetectedBootSector;
    use fsmnt::{ExtBackupSuperblock, ScanHit, ScanHitKind};

    fn backups(backups: &[(u64, u16)]) -> Vec<ExtBackupSuperblock> {
        backups
            .iter()
            .map(|&(offset, group)| ExtBackupSuperblock { offset, group })
            .collect()
    }

    fn ext_hit(offset: u64, folded: &[(u64, u16)]) -> ScanHit {
        ScanHit {
            offset,
            kind: ScanHitKind::Filesystem(DetectedBootSector::Ext),
            size_bytes: Some(4096),
            backup_superblocks: backups(folded),
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
                start_before_medium: None,
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
        assert_eq!(
            note_column(&orphan),
            "backup superblock of group 3; filesystem start would be at 1024"
        );
    }

    #[test]
    fn a_slice_that_begins_inside_a_filesystem_says_so_and_names_its_witnesses() {
        let orphan = ScanHit {
            offset: 201_325_568,
            kind: ScanHitKind::ExtBackupSuperblock {
                group: 5,
                filesystem_start: None,
                start_before_medium: Some(469_762_048),
            },
            size_bytes: None,
            backup_superblocks: backups(&[
                (872_415_232, 7),
                (1_140_850_688, 9),
                (3_355_443_200, 25),
                (3_623_878_656, 27),
            ]),
        };
        assert_eq!(orphan.mount_offset(), None);
        assert_eq!(type_column(&orphan), "Ext (backup only)");
        assert_eq!(
            note_column(&orphan),
            "backup superblock of group 5, corroborated by groups 7, 9, 25, 27; the filesystem \
             starts 469762048 bytes before this medium — the image begins inside it"
        );
    }

    #[test]
    fn a_run_of_superblock_copies_is_reported_as_copies_not_as_a_start() {
        let copies = ScanHit {
            offset: 3_424_641_024,
            kind: ScanHitKind::ExtPrimaryCopies {
                copies: 50,
                last_offset: 3_428_098_048,
            },
            size_bytes: Some(3_959_422_976),
            backup_superblocks: Vec::new(),
        };
        assert_eq!(copies.mount_offset(), None);
        assert_eq!(type_column(&copies), "Ext (superblock copies)");
        assert_eq!(
            note_column(&copies),
            "50 copies of a primary superblock between 3424641024 and 3428098048, none followed \
             by its group descriptors — journal writes inside a filesystem, not a start"
        );

        let single = ScanHit {
            offset: 4096,
            kind: ScanHitKind::ExtPrimaryCopies {
                copies: 1,
                last_offset: 4096,
            },
            size_bytes: None,
            backup_superblocks: Vec::new(),
        };
        assert_eq!(
            note_column(&single),
            "one copy of a primary superblock at 4096, not followed by its group descriptors — a \
             journal write inside a filesystem, not a start"
        );
    }

    #[test]
    fn a_corroborated_copy_becomes_a_damaged_start_with_a_way_in() {
        let damaged = ScanHit {
            offset: 4096,
            kind: ScanHitKind::ExtPrimaryCopies {
                copies: 1,
                last_offset: 4096,
            },
            size_bytes: Some(4096),
            backup_superblocks: backups(&[(1_048_576, 1), (3_145_728, 3)]),
        };
        assert_eq!(damaged.mount_offset(), Some(4096));
        assert_eq!(type_column(&damaged), "Ext (table damaged)");
        assert_eq!(
            note_column(&damaged),
            "primary superblock whose descriptor table does not verify, but backups at groups \
             1, 3 name this offset as the start; mount with --offset 4096 --backup-superblock 1"
        );
    }
}
