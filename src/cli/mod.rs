//! Subcommand handlers and the helpers they share.
//!
//! `main.rs` owns the clap definitions and dispatches into this module:
//! [`source`] decides what the single `SOURCE` positional names, [`mount`]
//! mounts it, [`partitions`] and [`scan`] inspect it, [`size`] reads the
//! size expressions their offsets are written in, [`detach`] hands a mount
//! to a background process, [`logging`] installs the subscriber every
//! message goes through, and the helpers below are used by all of them.
//!
//! The division of output is deliberate: `println!` here is reserved for
//! what the command *produces* — the tables, and the mount lifecycle lines
//! a script may key on — while everything that describes how the command
//! got there is a `tracing` event, so `-q`, `-v` and `--log-file` control
//! it without changing what a pipeline reads.
//!
//! [`json`] is the same division stated for a program rather than a person:
//! each handler builds one typed report and then renders it, so the table
//! and the document are two views of one gathering rather than two paths
//! through the media.

pub(crate) mod detach;
pub(crate) mod json;
pub(crate) mod logging;
pub(crate) mod mount;
pub(crate) mod partitions;
pub(crate) mod scan;
pub(crate) mod size;
pub(crate) mod source;

#[cfg(test)]
mod tests;

pub(crate) use mount::handle_mount;
pub(crate) use partitions::{handle_drives, handle_partitions};
pub(crate) use scan::handle_scan;

use tracing::{info, warn};

use json::{
    BestEffort, MountReport, MountedEvent, OpenedEvent, Output, UnmountDocument, UnmountedEvent,
};

/// What every drive operation reports on a platform with no drive
/// enumerator, instead of the command not existing at all: the source
/// grammar is the same everywhere, so `fsmnt partitions 0` should say why
/// it cannot be answered here.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) const NO_DRIVE_SUPPORT: &str = "physical drives are not supported on this platform";

/// On Unix the mountpoint is a directory; create it if needed.
#[allow(
    clippy::unnecessary_wraps,
    reason = "fallible only on Unix; single signature keeps call sites clean"
)]
pub(crate) fn ensure_unix_mountpoint(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    if !std::path::Path::new(mountpoint).exists() {
        std::fs::create_dir_all(mountpoint)?;
    }
    #[cfg(not(unix))]
    let _ = mountpoint;
    Ok(())
}

/// Mount `fs` and block until the mount ends.
///
/// `report` is what the mount already established about itself — where the
/// filesystem was, how it was located, what the medium is short of — which
/// the backend needs the labels from and which `--json` emits as the
/// `opened` event. `substitutions` is the best-effort-read counter of the
/// source, when that mode is on; what it accumulated is reported once the
/// mount ends, since that is when the caller knows how much of what they
/// copied was really there.
pub(crate) fn block_on_mount(
    fs: Box<dyn fsmnt::TargetFilesystem>,
    mountpoint: &str,
    report: &MountReport,
    substitutions: Option<std::sync::Arc<fsmnt::device::ReadSubstitutions>>,
    output: Output,
) -> Result<(), Box<dyn std::error::Error>> {
    let mp_display = mountpoint.to_string();
    // Anything the driver did that departs from a plain open — a backup
    // boot sector or superblock standing in for the primary, a degraded
    // mode — is said out loud before the volume appears, so a scripted
    // mount leaves that fact in its log even at `-q`.
    let notices = fs.notices();
    for notice in &notices {
        warn!("{notice}");
    }
    if output.is_json() {
        json::print_event(&OpenedEvent::new(report, notices));
    }
    if substitutions.is_some() {
        warn!(
            "best-effort reads are on — data the source cannot provide is served as zeros; a \
             summary follows when the volume is unmounted"
        );
    }
    info!("mounting {} volume at {mountpoint}", report.filesystem);
    fsmnt::mount(
        fs,
        mountpoint,
        &report.fsname,
        &report.volname,
        report.size_bytes.unwrap_or(0),
        move || {
            if output.is_json() {
                // The pid is this process: it is the one holding the mount,
                // and the one `fsmnt unmount` releases it from.
                json::print_event(&MountedEvent::new(&mp_display, std::process::id()));
            } else {
                println!(
                    "Volume mounted at {mp_display}. Press Ctrl+C, or run 'fsmnt unmount \
                     {mp_display}' from another shell, to unmount."
                );
            }
        },
    )?;
    if output.is_json() {
        let best_effort = substitutions.as_deref().map(BestEffort::new);
        json::print_event(&UnmountedEvent::new(mountpoint, best_effort));
    } else {
        println!("Unmounted.");
    }
    if let Some(stats) = substitutions {
        report_substitutions(&stats);
    }
    Ok(())
}

/// Say how much of the media that was read turned out not to be there
/// (distinct bytes, each counted once however often it was re-read), or
/// that none of it was missing.
fn report_substitutions(stats: &fsmnt::device::ReadSubstitutions) {
    use size::format_size_precise;

    if !stats.any() {
        info!("best-effort reads: every byte that was read was present in the source");
        return;
    }
    // Bytes in front of the medium are named separately, and only when
    // there are any: they were not lost to a defect or a short dump, the
    // acquisition simply began after the filesystem did, and a report has
    // to be able to say which of the three happened.
    let absent = stats.absent_bytes();
    let head = if absent == 0 {
        String::new()
    } else {
        format!(
            ", {} before the start of the medium (the filesystem began before the acquisition)",
            format_size_precise(absent),
        )
    };
    warn!(
        "best-effort reads: {} of the media that was read was not there and came back as zeros \
         — {} past the end of the source{head}, {} in sectors that failed to read ({} read \
         error(s))",
        format_size_precise(stats.missing_bytes() + stats.errored_bytes() + absent),
        format_size_precise(stats.missing_bytes()),
        format_size_precise(stats.errored_bytes()),
        stats.read_errors(),
    );
}

/// Unmount whatever `fsmnt` has mounted at `mountpoint`.
pub(crate) fn handle_unmount(
    mountpoint: &str,
    output: Output,
) -> Result<(), Box<dyn std::error::Error>> {
    fsmnt::unmount(mountpoint)?;
    match output {
        Output::Json => json::print_document(&UnmountDocument::new(mountpoint)),
        Output::Human => println!("Unmounted {mountpoint}."),
    }
    Ok(())
}

/// Format a byte count for human display.
pub(crate) fn format_size(bytes: u64) -> String {
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

/// Format a length a medium may not know.
///
/// A drive whose size the operating system declines to report — and every
/// extent on it that is bounded by nothing else — carries 0, which the
/// layout types define as "unknown, running to the end". Printing that as
/// "0 MB" would state a fact nobody established.
pub(crate) fn format_media_size(bytes: u64) -> String {
    if bytes == 0 {
        return "unknown".to_string();
    }
    format_size(bytes)
}

/// Warn when the opened filesystem is larger than the bytes behind it.
///
/// The mount itself succeeds — the superblock is at the front — so without
/// this the shortfall only shows up later as per-file read errors, which
/// read like corruption rather than like a partial acquisition.
pub(crate) fn warn_if_truncated(truncated_by: Option<u64>, available_bytes: u64, medium: &str) {
    use size::format_size_precise;

    let Some(missing) = truncated_by else {
        return;
    };
    let claimed = available_bytes.saturating_add(missing);
    warn!(
        "filesystem claims {} but only {} are present in the {medium} ({} missing); reads past \
         that point will fail",
        format_size_precise(claimed),
        format_size_precise(available_bytes),
        format_size_precise(missing),
    );
}

/// Say what a partition ordinal was resolved against, whenever that was not
/// simply the table at the front of the medium.
///
/// The provenance of an offset matters as much as the offset: a table read
/// from the media, a table recovered from its backup copy and a table
/// *invented* by a scan are three different claims, and a report that
/// repeats the ordinal has to be able to say which one it is repeating.
pub(crate) fn warn_layout_origin(
    origin: Option<fsmnt::LayoutOrigin>,
    partition: Option<usize>,
    source: &source::Source,
) {
    match origin {
        Some(fsmnt::LayoutOrigin::Scan { stride }) => warn!(
            "partition {} is an entry of a SYNTHETIC table reconstructed by scanning the media \
             every {stride} bytes — no partition table was read from {source}, and the number is \
             valid only for this {} at this stride",
            partition.unwrap_or_default(),
            source.describe(),
        ),
        Some(fsmnt::LayoutOrigin::BackupTable) => warn!(
            "the partition table was recovered from the GPT backup header in the last sector; the \
             primary at the front of {source} is damaged"
        ),
        Some(fsmnt::LayoutOrigin::Table | fsmnt::LayoutOrigin::None) | None => {}
    }
}

/// Filesystem type label for a detected boot sector.
pub(crate) fn fs_label(detected: fsmnt::device::DetectedBootSector) -> &'static str {
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

/// Build the driver registry, attaching any supplied `BitLocker`
/// credentials.
///
/// Credentials ride on the driver because `FilesystemDriver::open` takes no
/// credentials parameter.  A driver with none still unlocks volumes whose
/// protection is suspended, via the clear key.
pub(crate) fn build_registry(
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
