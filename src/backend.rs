//! Platform mount-backend dispatch: FUSE on Unix, Dokan on Windows.
//!
//! The umbrella crate exposes one [`mount`] / [`unmount`] / [`is_mounted`]
//! surface; this module chooses the backend crate at compile time so
//! callers never name `fsmnt_fuse` or `fsmnt_dokan` themselves.

use fsmnt_core::TargetFilesystem;

/// Mount a [`TargetFilesystem`] as a read-only volume.
///
/// - `mountpoint` — directory path (Unix) or drive letter / directory
///   (Windows, e.g. `"Z:"`).
/// - `fsname` — filesystem type label (e.g. `"ntfs"`, `"fat32"`).
/// - `volname` — volume label shown in the OS file manager.
/// - `total_bytes` — total size of the underlying volume in bytes, reported
///   by the OS in volume properties.  Pass 0 to fall back to the
///   filesystem's [`TargetFilesystem::total_size`].
/// - `on_mount` — called once the volume is successfully mounted and
///   accessible, *before* blocking.
///
/// Blocks until the mount ends, which happens when the process is asked to
/// stop — Ctrl+C on either platform, plus `SIGTERM`/`SIGHUP` on Unix and
/// console close, logoff, or shutdown on Windows — or when the volume is
/// unmounted from elsewhere, by [`unmount`], `fusermount -u`, or `umount`.
/// The volume is unmounted by the time the function returns.
///
/// # Errors
///
/// Returns an error if the platform mount backend fails to create the
/// volume (e.g. missing FUSE/Dokan driver or an invalid mountpoint), or on
/// platforms with no mount backend.
pub fn mount(
    fs: Box<dyn TargetFilesystem>,
    mountpoint: &str,
    fsname: &str,
    volname: &str,
    total_bytes: u64,
    on_mount: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        fsmnt_fuse::mount(fs, mountpoint, fsname, volname, total_bytes, on_mount)
    }
    #[cfg(windows)]
    {
        fsmnt_dokan::mount(fs, mountpoint, fsname, volname, total_bytes, on_mount)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (fs, mountpoint, fsname, volname, total_bytes, on_mount);
        Err("fsmnt is not supported on this platform".into())
    }
}

/// Unmount the volume at `mountpoint`, from any process.
///
/// - `mountpoint` — the directory a volume was mounted on (Unix), or the
///   drive letter / directory it was mounted on (Windows).
///
/// This is how a mount started elsewhere is stopped: a [`mount`] call
/// blocked on that mountpoint returns and unmounts. On Windows it also
/// clears a directory mountpoint that a killed mount process left behind
/// as a stale reparse point, which is otherwise unusable — `ls` and
/// `rmdir` both fail on it with "no such device".
///
/// # Errors
///
/// Returns an error if nothing is mounted at `mountpoint`, the unmount is
/// refused (for example a busy volume on Unix), or the platform has no
/// mount backend.
pub fn unmount(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        fsmnt_fuse::unmount(mountpoint)
    }
    #[cfg(windows)]
    {
        fsmnt_dokan::unmount(mountpoint)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = mountpoint;
        Err("fsmnt is not supported on this platform".into())
    }
}

/// Whether a volume appears to be mounted at `mountpoint`.
///
/// Best effort, and observed from outside the mounting process: on Unix
/// the mountpoint carries a different device number than its parent
/// directory, on Windows a mounted drive letter has a readable root and a
/// mounted directory carries a reparse point with a readable volume behind
/// it. A Windows directory mountpoint left stale by a killed mount process
/// answers `false`, since nothing is mounted there any more, even though it
/// still needs [`unmount`] to become reusable.
#[must_use]
pub fn is_mounted(mountpoint: &str) -> bool {
    #[cfg(unix)]
    {
        fsmnt_fuse::is_mounted(mountpoint)
    }
    #[cfg(windows)]
    {
        fsmnt_dokan::is_mounted(mountpoint)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = mountpoint;
        false
    }
}
