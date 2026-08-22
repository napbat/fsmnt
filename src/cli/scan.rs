//! The `scan` subcommand: look for filesystems anywhere in a medium.
//!
//! A drive whose partition table was wiped and an image of one are the same
//! forensic situation, so both are searched the same way and produce the
//! same table; only the identity line at the top differs, because an image
//! has a container format and a drive has a model.
//!
//! Every hit becomes one [`ScanHitEntry`] — offsets and numbers, the note
//! the table prints, and the argument list that opens it — which the one
//! [`ScanDocument`] then renders as the table below or as JSON. The `NOTE`
//! column and the JSON `note` are therefore the same sentence, and the
//! mount command a person reads is the same list a program receives.

use std::io::Write;

use fsmnt::device::DetectedBootSector;
use fsmnt::{ImageFormat, ScanHit, ScanHitKind, ScanOptions};

use super::format_media_size;
use super::output::{
    BackupSuperblockEntry, Output, Report, ScanDocument, ScanHitEntry, Shape, media_size,
};
use super::size::DEFAULT_SECTOR_SIZE;
use super::source::{Source, resolve};
use crate::ScanArgs;

/// What the medium is, gathered before the scan and spent on the document.
struct Medium {
    /// Length in bytes, when anything established one.
    size_bytes: Option<u64>,
    /// Container format, for an image.
    format: Option<ImageFormat>,
    /// Model, for a drive.
    model: Option<String>,
}

/// Search a drive or a disk image for filesystem starts and print the
/// candidate offsets.
///
/// # Errors
///
/// Returns an error if the source is a directory, cannot be resolved, or
/// cannot be read to the end.
pub(crate) fn handle_scan(
    args: &ScanArgs,
    output: Output,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve(&args.source, args.source_kind())?;
    let (medium, hits) = match &source {
        Source::Directory(path) => {
            return Err(format!(
                "{} is a directory; this command takes a disk image or a drive",
                path.display()
            )
            .into());
        }
        Source::Image(path) => scan_image(args, &source, path)?,
        Source::Drive(drive) => scan_drive(args, &source, drive)?,
    };

    let sector_size = args.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE);
    output.emit(&ScanDocument::new(
        &source,
        args.stride,
        sector_size,
        medium.size_bytes,
        medium.format,
        medium.model,
        hit_entries(&hits, sector_size),
    ));
    Ok(())
}

/// Scan a disk image.
fn scan_image(
    args: &ScanArgs,
    source: &Source,
    path: &std::path::Path,
) -> Result<(Medium, Vec<ScanHit>), Box<dyn std::error::Error>> {
    let reader = fsmnt::ImageReader::open(path)?;
    let medium = Medium {
        size_bytes: media_size(reader.len()),
        format: Some(reader.format()),
        model: None,
    };
    drop(reader);
    announce(source, args.stride);
    let hits = fsmnt::scan_image_with_options(path, ScanOptions::new().with_stride(args.stride))?;
    Ok((medium, hits))
}

/// Scan a physical drive, announcing it the way an image announces itself.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn scan_drive(
    args: &ScanArgs,
    source: &Source,
    drive: &fsmnt::device::HostDriveId,
) -> Result<(Medium, Vec<ScanHit>), Box<dyn std::error::Error>> {
    use fsmnt::HostDrives;
    use fsmnt::device::HostDriveEnumerator;

    let info = HostDrives::get_drive_info(drive).ok();
    let medium = Medium {
        size_bytes: info.as_ref().and_then(|info| info.size_bytes),
        format: None,
        model: info.and_then(|info| info.model),
    };
    announce(source, args.stride);
    let hits = fsmnt::scan_drive::<HostDrives>(drive, ScanOptions::new().with_stride(args.stride))?;
    Ok((medium, hits))
}

/// Physical drives cannot be scanned on this platform.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn scan_drive(
    _args: &ScanArgs,
    _source: &Source,
    _drive: &fsmnt::device::HostDriveId,
) -> Result<(Medium, Vec<ScanHit>), Box<dyn std::error::Error>> {
    Err(super::NO_DRIVE_SUPPORT.into())
}

/// Say what is about to be read, before a scan that may take a while.
///
/// A log line rather than a printed one, because it says what the command
/// is *doing*: what the medium turned out to be is the first line of the
/// document below, where a JSON reader gets it as fields.
fn announce(source: &Source, stride: u64) {
    tracing::info!("scanning {source} every {stride} bytes for filesystem starts");
}

/// Number and describe every hit, in scan order.
fn hit_entries(hits: &[ScanHit], sector_size: u32) -> Vec<ScanHitEntry> {
    // The `#` column is the SYNTHETIC ordinal `fsmnt mount --scan
    // --partition` takes: the position among mountable hits, in scan order —
    // the same numbering `partitions --scan` prints. It exists only for this
    // medium at this stride; partition tables get no number because they are
    // not mountable.
    let mut ordinal = 0_usize;
    hits.iter()
        .map(|hit| {
            let number = hit.mount_offset().is_some().then(|| {
                let shown = ordinal;
                ordinal += 1;
                shown
            });
            hit_entry(hit, number, sector_size)
        })
        .collect()
}

/// Everything one hit has to say.
fn hit_entry(hit: &ScanHit, ordinal: Option<usize>, sector_size: u32) -> ScanHitEntry {
    let (group, filesystem_start, start_before_medium) = match hit.kind {
        ScanHitKind::ExtBackupSuperblock {
            group,
            filesystem_start,
            start_before_medium,
        } => (Some(group), filesystem_start, start_before_medium),
        ScanHitKind::Filesystem(_)
        | ScanHitKind::PartitionTable(_)
        | ScanHitKind::ExtPrimaryCopies { .. } => (None, None, None),
    };
    let (copies, last_offset) = match hit.kind {
        ScanHitKind::ExtPrimaryCopies {
            copies,
            last_offset,
        } => (Some(copies), Some(last_offset)),
        ScanHitKind::Filesystem(_)
        | ScanHitKind::PartitionTable(_)
        | ScanHitKind::ExtBackupSuperblock { .. } => (None, None),
    };
    ScanHitEntry {
        offset: hit.offset,
        sector: sector(hit.offset, sector_size),
        kind: hit_kind(hit),
        filesystem: Some(hit_filesystem(hit)),
        size_bytes: hit.size_bytes,
        mount_offset: hit.mount_offset(),
        ordinal,
        backup_superblocks: BackupSuperblockEntry::all(hit),
        group,
        filesystem_start,
        start_before_medium,
        copies,
        last_offset,
        note: note_column(hit),
        mount_command: mount_command(hit),
    }
}

/// The wire name for what a hit is.
const fn hit_kind(hit: &ScanHit) -> &'static str {
    match hit.kind {
        ScanHitKind::Filesystem(_) => "filesystem",
        ScanHitKind::PartitionTable(_) => "partition_table",
        ScanHitKind::ExtBackupSuperblock { .. } => "ext_backup_superblock",
        ScanHitKind::ExtPrimaryCopies { .. } => "ext_primary_copies",
    }
}

/// The format a hit is evidence of.
///
/// A superblock is not a filesystem, but it is evidence of one and of which
/// kind, so the ext hits name `ext` rather than nothing.
const fn hit_filesystem(hit: &ScanHit) -> DetectedBootSector {
    match hit.kind {
        ScanHitKind::Filesystem(detected) | ScanHitKind::PartitionTable(detected) => detected,
        ScanHitKind::ExtBackupSuperblock { .. } | ScanHitKind::ExtPrimaryCopies { .. } => {
            DetectedBootSector::Ext
        }
    }
}

/// The offset in sectors, when it is a whole number of them.
fn sector(offset: u64, sector_size: u32) -> Option<u64> {
    let sector_size = u64::from(sector_size);
    if sector_size == 0 || !offset.is_multiple_of(sector_size) {
        return None;
    }
    Some(offset / sector_size)
}

/// The arguments a mount of this hit takes, appended to
/// `fsmnt mount SOURCE MOUNTPOINT`.
///
/// The same command the notes below spell out in prose, as a list nobody has
/// to re-quote: `None` where there is no way in at all, which is exactly
/// where the table prints no `#` and no suggestion either.
fn mount_command(hit: &ScanHit) -> Option<Vec<String>> {
    if let Some(offset) = hit.mount_offset() {
        let mut command = vec!["--offset".to_string(), offset.to_string()];
        // A start whose own descriptor table does not verify is only openable
        // through the backup that named it as a start, which is what the note
        // for that row says too.
        if matches!(
            hit.kind,
            ScanHitKind::ExtBackupSuperblock { .. } | ScanHitKind::ExtPrimaryCopies { .. }
        ) && let Some(group) = hit.backup_superblock_group()
        {
            command.push("--backup-superblock".to_string());
            command.push(group.to_string());
        }
        return Some(command);
    }
    Some(head_absent_flags(
        hit.head_absent()?,
        hit.backup_superblock_group()?,
    ))
}

impl Report for ScanDocument {
    const SHAPE: Shape = Shape::Document;

    /// What was searched, what was found in it, and the two ways to mount
    /// one of the hits.
    fn render_text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        write_medium(out, self)?;
        write_hits(out, self)
    }
}

/// The identity line: what the medium is, and how long.
///
/// An image has a container format and a drive has a model, which is the
/// only difference between the two — they are the same forensic situation
/// and produce the same table.
fn write_medium(out: &mut dyn Write, document: &ScanDocument) -> std::io::Result<()> {
    let source = document.source.name();
    let size = document
        .size_bytes
        .map_or_else(|| "unknown".to_string(), format_media_size);
    match document.format {
        Some(format) => writeln!(out, "{source}: {format} image, {size}"),
        None => writeln!(
            out,
            "{source}: drive ({}), {size}",
            document.model.as_deref().unwrap_or("unknown model"),
        ),
    }
}

/// Write what the scan found, and the two ways to mount one of them.
fn write_hits(out: &mut dyn Write, document: &ScanDocument) -> std::io::Result<()> {
    let source = document.source.name();
    if document.hits.is_empty() {
        return writeln!(
            out,
            "\nNo filesystems found. A filesystem whose start is not aligned to {} bytes needs a \
             finer scan: --stride 512.",
            document.stride
        );
    }

    writeln!(
        out,
        "\n{:>4}  {:>14} {:>14}  {:<22} {:>12}  NOTE",
        "#", "OFFSET", "SECTOR", "TYPE", "SIZE"
    )?;
    for hit in &document.hits {
        writeln!(
            out,
            "{:>4}  {:>14} {:>14}  {:<22} {:>12}  {}",
            hit.ordinal
                .map_or_else(|| "-".to_string(), |ordinal| ordinal.to_string()),
            hit.offset,
            hit.sector
                .map_or_else(|| "-".to_string(), |sector| format!("{sector}s")),
            type_column(hit),
            hit.size_bytes
                .map_or_else(|| "-".to_string(), format_media_size),
            hit.note,
        )?;
    }

    // A filesystem this medium begins *inside* has no offset here to mount
    // at, so it never gets a `#` — but it is mountable, and the command
    // that does it is worth spelling out in full.
    let begins_inside = document
        .hits
        .iter()
        .find(|hit| hit.start_before_medium.is_some() && hit.mount_command.is_some());

    let Some(first) = document.hits.iter().find(|hit| hit.mount_offset.is_some()) else {
        if let Some(hit) = begins_inside {
            return writeln!(
                out,
                "\nNo row above is the start of a filesystem, but this medium is a slice of one. \
                 Mount it with:\n  fsmnt mount {source} <MOUNTPOINT> {}",
                command_line(hit),
            );
        }
        // Every row above is evidence *about* a filesystem rather than the
        // start of one, so there is no offset to offer. Saying that is more
        // use than a mount command with nothing to put in it.
        return writeln!(
            out,
            "\nNothing found is mountable: no row above is the start of a filesystem. A start \
             that is not aligned to {} bytes needs a finer scan: --stride 512.",
            document.stride
        );
    };
    let offset = first.mount_offset.unwrap_or(first.offset);
    let stride_flag = if document.stride == fsmnt::DEFAULT_STRIDE {
        String::new()
    } else {
        format!(" --stride {}", document.stride)
    };
    writeln!(
        out,
        "\nMount one with: fsmnt mount {source} <MOUNTPOINT> --offset {offset}\n\
         or by its # above:  fsmnt mount {source} <MOUNTPOINT> --scan{stride_flag} \
         --partition <#>   (# is synthetic — from this scan, not from the {})",
        document.source.describe(),
    )?;
    if let Some(hit) = begins_inside {
        writeln!(
            out,
            "\nOne row above has no #: its filesystem starts before this medium. Mount that one \
             with:\n  fsmnt mount {source} <MOUNTPOINT> {}",
            command_line(hit),
        )?;
    }
    Ok(())
}

/// A hit's mount arguments as a person would type them.
fn command_line(hit: &ScanHitEntry) -> String {
    hit.mount_command
        .as_ref()
        .map(|command| command.join(" "))
        .unwrap_or_default()
}

/// The type column: the detected filesystem, or what a lone superblock is.
fn type_column(hit: &ScanHitEntry) -> String {
    match hit.kind {
        "ext_backup_superblock" => "Ext (backup only)".to_string(),
        // Copies of a primary that nothing corroborates are just copies;
        // once a backup names the offset as a start, the same bytes become a
        // filesystem whose descriptor table is broken.
        "ext_primary_copies" => if hit.mount_offset.is_some() {
            "Ext (table damaged)"
        } else {
            "Ext (superblock copies)"
        }
        .to_string(),
        _ => hit
            .filesystem
            .map_or_else(|| "-".to_string(), |detected| format!("{detected:?}")),
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
        // There is no offset on this medium to mount at — the start is
        // behind its first byte — so the note carries the flags that say
        // so instead, the way the damaged-primary note carries its own.
        (None, Some(before)) => write!(
            note,
            "; the filesystem starts {before} bytes before this medium — the image begins inside \
             it; mount with {}",
            head_absent_flags(
                before,
                hit.backup_superblock_group().unwrap_or(u32::from(group))
            )
            .join(" "),
        ),
        (None, None) => write!(note, "; its filesystem starts before this medium"),
    };
    note
}

/// The flags that open a volume the medium begins inside: the absent head,
/// the surviving copy to read the metadata from, and the two options that
/// make the rest of it recoverable.
///
/// `--salvage` and `--best-effort-reads` are part of the suggestion rather
/// than an afterthought because neither is optional in practice here: the
/// root directory usually lived in the absent head, and every read that
/// reaches into it has to come back as counted zeros for the sweep to get
/// past it.
fn head_absent_flags(before: u64, group: u32) -> Vec<String> {
    vec![
        "--offset".to_string(),
        format!("-{before}"),
        "--backup-superblock".to_string(),
        group.to_string(),
        "--salvage".to_string(),
        "--best-effort-reads".to_string(),
    ]
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
    // Deliberately vague about *which* test the copy failed: a run folds
    // together copies with no group descriptors behind them and copies whose
    // descriptors verified but pointed at no root directory, and the reader
    // wants the same thing from both — the offset is not a start.
    if copies == 1 {
        return format!(
            "one copy of a primary superblock at {}, without the filesystem a start has behind it \
             — a journal write inside one, not a start",
            hit.offset,
        );
    }
    format!(
        "{copies} copies of a primary superblock between {} and {last_offset}, none with the \
         filesystem a start has behind it — journal writes inside one, not starts",
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
    use super::{
        DEFAULT_SECTOR_SIZE, Report, ScanDocument, Source, backups_note, hit_entries, hit_entry,
        note_column, sector, type_column,
    };
    use fsmnt::device::DetectedBootSector;
    use fsmnt::{ExtBackupSuperblock, ImageFormat, ScanHit, ScanHitKind};

    /// Render a document the way `emit` writes it to a terminal.
    fn text(document: &ScanDocument) -> String {
        let mut rendered = Vec::new();
        document
            .render_text(&mut rendered)
            .expect("a rendering into memory cannot fail");
        String::from_utf8(rendered).expect("the rendering is UTF-8")
    }

    /// The expected rendering, written one printed line per element.
    fn lines(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

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

    /// The type column of a hit, read off the entry the document carries.
    fn type_of(hit: &ScanHit) -> String {
        type_column(&hit_entry(hit, None, DEFAULT_SECTOR_SIZE))
    }

    /// The mount command a hit offers, as a list.
    fn command_of(hit: &ScanHit) -> Option<Vec<String>> {
        hit_entry(hit, None, DEFAULT_SECTOR_SIZE).mount_command
    }

    #[test]
    fn offsets_are_also_shown_in_sectors_when_they_divide_evenly() {
        assert_eq!(sector(270_532_608, 512), Some(528_384));
        assert_eq!(sector(0, 512), Some(0));
        assert_eq!(sector(270_533_632, 4096), None);
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
        assert_eq!(type_of(&table), "GptPartitioned");
        assert_eq!(command_of(&table), None, "a table is not a filesystem");

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
        assert_eq!(type_of(&orphan), "Ext (backup only)");
        assert_eq!(
            note_column(&orphan),
            "backup superblock of group 3; filesystem start would be at 1024"
        );
        assert_eq!(
            command_of(&orphan),
            Some(vec![
                "--offset".to_string(),
                "1024".to_string(),
                "--backup-superblock".to_string(),
                "3".to_string(),
            ]),
            "a backup-only hit must offer a command that can actually open it",
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
        assert_eq!(
            orphan.mount_offset(),
            None,
            "no offset on this medium is the start of that filesystem"
        );
        assert_eq!(
            orphan.head_absent(),
            Some(469_762_048),
            "but the distance back to its start is known, and that is the way in"
        );
        assert_eq!(orphan.backup_superblock_group(), Some(5));
        assert_eq!(type_of(&orphan), "Ext (backup only)");
        assert_eq!(
            note_column(&orphan),
            "backup superblock of group 5, corroborated by groups 7, 9, 25, 27; the filesystem \
             starts 469762048 bytes before this medium — the image begins inside it; mount with \
             --offset -469762048 --backup-superblock 5 --salvage --best-effort-reads"
        );
        let command = command_of(&orphan).expect("the way in is a command");
        assert_eq!(
            command,
            [
                "--offset",
                "-469762048",
                "--backup-superblock",
                "5",
                "--salvage",
                "--best-effort-reads",
            ],
        );
        assert!(
            note_column(&orphan).ends_with(&command.join(" ")),
            "the note and the argument list are the same command"
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
        assert_eq!(type_of(&copies), "Ext (superblock copies)");
        assert_eq!(
            note_column(&copies),
            "50 copies of a primary superblock between 3424641024 and 3428098048, none with the \
             filesystem a start has behind it — journal writes inside one, not starts"
        );
        assert_eq!(command_of(&copies), None);

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
            "one copy of a primary superblock at 4096, without the filesystem a start has behind \
             it — a journal write inside one, not a start"
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
        assert_eq!(type_of(&damaged), "Ext (table damaged)");
        assert_eq!(
            note_column(&damaged),
            "primary superblock whose descriptor table does not verify, but backups at groups \
             1, 3 name this offset as the start; mount with --offset 4096 --backup-superblock 1"
        );
        assert_eq!(
            command_of(&damaged),
            Some(vec![
                "--offset".to_string(),
                "4096".to_string(),
                "--backup-superblock".to_string(),
                "1".to_string(),
            ]),
            "the note's command and the argument list say the same thing"
        );
    }

    #[test]
    fn the_ordinal_counts_mountable_hits_in_scan_order() {
        let hits = vec![
            ScanHit {
                offset: 0,
                kind: ScanHitKind::PartitionTable(DetectedBootSector::GptPartitioned),
                size_bytes: None,
                backup_superblocks: Vec::new(),
            },
            ext_hit(270_532_608, &[(1024, 1)]),
            ScanHit {
                offset: 201_325_568,
                kind: ScanHitKind::ExtBackupSuperblock {
                    group: 5,
                    filesystem_start: None,
                    start_before_medium: Some(469_762_048),
                },
                size_bytes: None,
                backup_superblocks: Vec::new(),
            },
            ext_hit(903_872_512, &[]),
        ];

        let entries = hit_entries(&hits, DEFAULT_SECTOR_SIZE);
        let ordinals: Vec<Option<usize>> = entries.iter().map(|entry| entry.ordinal).collect();
        assert_eq!(
            ordinals,
            [None, Some(0), None, Some(1)],
            "only a hit with an offset to mount at is numbered, and the numbers do not skip"
        );
        assert_eq!(entries[1].kind, "filesystem");
        assert_eq!(entries[1].sector, Some(528_384));
        assert_eq!(entries[2].kind, "ext_backup_superblock");
        assert_eq!(entries[2].group, Some(5));
        assert_eq!(entries[2].start_before_medium, Some(469_762_048));
        assert_eq!(entries[0].backup_superblocks.len(), 0);
        assert_eq!(entries[1].backup_superblocks.len(), 1);
        assert_eq!(entries[1].backup_superblocks[0].group, 1);
    }

    #[test]
    fn a_hit_serializes_with_the_numbers_and_the_note_the_table_prints() {
        let hits = vec![ext_hit(270_532_608, &[(1024, 1), (2048, 3)])];
        let entries = hit_entries(&hits, DEFAULT_SECTOR_SIZE);
        let value = serde_json::to_value(&entries[0]).expect("a hit serializes");

        assert_eq!(value["offset"], 270_532_608_u64);
        assert_eq!(value["sector"], 528_384_u64);
        assert_eq!(value["kind"], "filesystem");
        assert_eq!(value["filesystem"], "ext");
        assert_eq!(value["size_bytes"], 4096);
        assert_eq!(value["mount_offset"], 270_532_608_u64);
        assert_eq!(value["ordinal"], 0);
        assert_eq!(value["group"], serde_json::Value::Null);
        assert_eq!(value["copies"], serde_json::Value::Null);
        assert_eq!(value["note"], "2 backup superblocks (groups 1, 3)");
        assert_eq!(
            value["backup_superblocks"],
            serde_json::json!([{"offset": 1024, "group": 1}, {"offset": 2048, "group": 3}]),
        );
        assert_eq!(
            value["mount_command"],
            serde_json::json!(["--offset", "270532608"]),
        );
    }

    #[test]
    fn the_table_a_person_reads_is_the_document_rendered_as_text() {
        let hits = vec![
            ScanHit {
                offset: 0,
                kind: ScanHitKind::PartitionTable(DetectedBootSector::MbrPartitioned),
                size_bytes: None,
                backup_superblocks: Vec::new(),
            },
            ScanHit {
                size_bytes: Some(3_300_000_000),
                ..ext_hit(270_532_608, &[(1024, 1), (2048, 3)])
            },
        ];
        let document = ScanDocument::new(
            &Source::Image("disk.bin".into()),
            fsmnt::DEFAULT_STRIDE,
            DEFAULT_SECTOR_SIZE,
            Some(4_000_000_000),
            Some(ImageFormat::Raw),
            None,
            hit_entries(&hits, DEFAULT_SECTOR_SIZE),
        );

        assert_eq!(
            text(&document),
            lines(&[
                "disk.bin: raw image, 4.0 GB",
                "",
                "   #          OFFSET         SECTOR  TYPE                           SIZE  NOTE",
                "   -               0             0s  MbrPartitioned                    -  \
                 partition table; list it with `fsmnt partitions`",
                "   0       270532608        528384s  Ext                          3.3 GB  \
                 2 backup superblocks (groups 1, 3)",
                "",
                "Mount one with: fsmnt mount disk.bin <MOUNTPOINT> --offset 270532608",
                "or by its # above:  fsmnt mount disk.bin <MOUNTPOINT> --scan --partition <#>   \
                 (# is synthetic — from this scan, not from the disk image)",
            ]),
            "the `#`, the note and the offset are the entry's own fields, laid out in columns"
        );
    }

    #[test]
    fn a_scan_that_found_nothing_still_says_what_it_searched() {
        let document = ScanDocument::new(
            &Source::Drive(fsmnt::device::HostDriveId::new("0")),
            fsmnt::DEFAULT_STRIDE,
            DEFAULT_SECTOR_SIZE,
            None,
            None,
            None,
            Vec::new(),
        );

        assert_eq!(
            text(&document),
            lines(&[
                "0: drive (unknown model), unknown",
                "",
                "No filesystems found. A filesystem whose start is not aligned to 4096 bytes \
                 needs a finer scan: --stride 512.",
            ]),
            "a drive names its model where an image names its container format, and a length \
             nobody established is not printed as 0"
        );
    }
}
