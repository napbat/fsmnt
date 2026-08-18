//! Subcommand handlers and the helpers they share.
//!
//! `main.rs` owns the clap definitions and dispatches into this module:
//! [`mount`] implements the three mounting commands, [`partitions`] the two
//! inspection commands, [`scan`] searches media no partition table
//! describes, [`size`] reads the size expressions their offsets are written
//! in, [`detach`] hands a mount to a background process, and the helpers
//! below are used by all of them.

pub(crate) mod detach;
pub(crate) mod mount;
pub(crate) mod partitions;
pub(crate) mod scan;
pub(crate) mod size;

#[cfg(test)]
mod tests;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) use mount::{MountDeviceOptions, handle_mount_device};
pub(crate) use mount::{MountImageOptions, handle_mount, handle_mount_image};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) use partitions::handle_drives;
pub(crate) use partitions::handle_partitions;
pub(crate) use scan::{ScanImageOptions, handle_scan};

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

/// Mount `fs` and block until the mount ends, printing progress.
pub(crate) fn block_on_mount(
    fs: Box<dyn fsmnt::TargetFilesystem>,
    mountpoint: &str,
    kind: &str,
    volname: &str,
    fsname: &str,
    total_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mp_display = mountpoint.to_string();
    println!("Mounting {kind} volume at {mountpoint}...");
    fsmnt::mount(fs, mountpoint, fsname, volname, total_bytes, move || {
        println!(
            "Volume mounted at {mp_display}. Press Ctrl+C, or run 'fsmnt unmount {mp_display}' \
             from another shell, to unmount."
        );
    })?;
    println!("Unmounted.");
    Ok(())
}

/// Unmount whatever `fsmnt` has mounted at `mountpoint`.
pub(crate) fn handle_unmount(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    fsmnt::unmount(mountpoint)?;
    println!("Unmounted {mountpoint}.");
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

/// Warn on stderr when the opened filesystem is larger than the bytes
/// behind it.
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
    eprintln!(
        "warning: filesystem claims {} but only {} are present in the {medium} ({} missing); \
         reads past that point will fail",
        format_size_precise(claimed),
        format_size_precise(available_bytes),
        format_size_precise(missing),
    );
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
