//! Dokan backend for Windows.
//!
//! Presents a [`TargetFilesystem`] as a read-only Windows volume via
//! [Dokan](https://dokan-dev.github.io/).  The volume can be mounted to a
//! drive letter (e.g. `Z:`) or an empty NTFS directory.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Utc};

use fsmnt_core::{FsMetadata, TargetFilesystem, filter_entries};

use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter,
    FileTimeOperation, FillDataResult, FindData, IO_SECURITY_CONTEXT, MountFlags, MountOptions,
    OperationInfo, OperationResult, VolumeInfo,
};
use tracing::{debug, trace, warn};
use widestring::{U16CStr, U16CString};
use windows_sys::Win32::{
    Foundation::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_UNSUCCESSFUL},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    },
    System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    },
};

/// Kernel-mode create disposition: overwrite existing file.
const FILE_SUPERSEDE: u32 = 0;
/// Kernel-mode create disposition: create new file (fail if exists).
const FILE_CREATE: u32 = 2;
/// Kernel-mode create disposition: overwrite existing (fail if not exists).
const FILE_OVERWRITE: u32 = 4;
/// Kernel-mode create disposition: open or create and overwrite.
const FILE_OVERWRITE_IF: u32 = 5;
/// Kernel-mode create option: delete file when last handle is closed.
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// Signal flag set by the console control handler to request unmount.
static STOP: AtomicBool = AtomicBool::new(false);

/// Set by [`mount`] once the volume has been released, so the console
/// control handler can tell that teardown finished.
static UNMOUNTED: AtomicBool = AtomicBool::new(false);

/// How long the console control handler waits for [`mount`] to finish
/// unmounting on a close, logoff, or shutdown event.  Windows terminates
/// the process as soon as the handler returns for those events, and gives
/// it only about five seconds in total.
const TEARDOWN_WAIT: Duration = Duration::from_secs(4);

/// How long [`unmount`] waits for the driver to release a mount point
/// after accepting the request.
const UNMOUNT_RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`unmount`] keeps re-asking the driver to remove a mount point
/// that is still mounted (see [`remove_mount_point`]).
const UNMOUNT_RETRY_WINDOW: Duration = Duration::from_secs(5);

/// Gap between the unmount retries and release checks above.
const RETRY_POLL: Duration = Duration::from_millis(100);

/// File attributes of a directory mountpoint.  These raw bits are what
/// identifies one: the mount-point reparse tag makes `FileType::is_dir`
/// report a symlink rather than the directory it is.
const MOUNTPOINT_ATTRIBUTES: u32 = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;

/// Console control handler: request a clean unmount on Ctrl+C, Ctrl+Break,
/// console close, logoff, or system shutdown.
///
/// `taskkill /F` is `TerminateProcess`, which no handler — here or anywhere
/// else — can intercept.  The Dokan driver still drops the volume when the
/// process dies, but a directory mountpoint can be left behind as a stale
/// reparse point; [`unmount`] clears that.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            // The process keeps running, so the mount loop gets to unmount
            // and return on its own.
            debug!(ctrl_type, "console interrupt received, requesting unmount");
            STOP.store(true, Ordering::SeqCst);
            1 // handled
        }
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            // For these events the process is terminated as soon as the
            // handler returns, so wait here until the volume is released.
            debug!(
                ctrl_type,
                "console shutdown event received, waiting for teardown"
            );
            STOP.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + TEARDOWN_WAIT;
            while !UNMOUNTED.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            1 // handled
        }
        _ => 0,
    }
}

/// Convert `Option<DateTime<Utc>>` to [`SystemTime`], falling back to the
/// Unix epoch when `None`.
fn to_system_time(dt: Option<DateTime<Utc>>) -> SystemTime {
    dt.map_or(SystemTime::UNIX_EPOCH, SystemTime::from)
}

/// Mounts `fs` as a read-only Dokan volume at `mountpoint`.
///
/// Calls `on_mount` once the volume is successfully mounted, then blocks
/// the calling thread until Ctrl+C — or until another process removes the
/// mount point, which is what [`unmount`] does.  Uses a Windows console
/// control handler directly (instead of `ctrlc`) because Dokan installs
/// its own handler that can conflict.
///
/// The volume is always unmounted before this returns, and a directory
/// mountpoint is left as an ordinary directory rather than a dangling
/// reparse point.
///
/// # Errors
///
/// Returns an error if the mountpoint is not valid UTF-16, the Dokan
/// driver is not installed, or the volume cannot be mounted.
pub fn mount(
    fs: Box<dyn TargetFilesystem>,
    mountpoint: &str,
    fsname: &str,
    volname: &str,
    total_bytes: u64,
    on_mount: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    dokan::init();

    let handler = DokanFs::new(fs, fsname.to_string(), volname.to_string(), total_bytes);
    let wide_path = U16CString::from_str(mountpoint)?;
    let options = MountOptions {
        flags: MountFlags::WRITE_PROTECT,
        ..Default::default()
    };

    let mut mounter = FileSystemMounter::new(&handler, &wide_path, &options);
    let file_system = mounter.mount()?;
    debug!(mountpoint, fsname, volname, "volume mounted");

    on_mount();

    STOP.store(false, Ordering::SeqCst);
    UNMOUNTED.store(false, Ordering::SeqCst);
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }

    // Watch for the stop signal on a second thread, because dropping
    // `file_system` is what blocks until the volume is closed.  Waiting on
    // the drop rather than on the signal alone means another process
    // removing the mount point (see [`unmount`]) also ends the mount.
    let closed = Arc::new(AtomicBool::new(false));
    let watcher = {
        let closed = Arc::clone(&closed);
        let wide_path = wide_path.clone();
        std::thread::spawn(move || {
            while !STOP.load(Ordering::SeqCst) && !closed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
            }
            if STOP.load(Ordering::SeqCst) {
                debug!("stop requested, removing the mount point");
                let _ = dokan::unmount(&wide_path);
            }
        })
    };

    // Dokan callbacks keep running on other threads until the volume is
    // released.
    drop(file_system);
    closed.store(true, Ordering::SeqCst);
    let _ = watcher.join();

    dokan::shutdown();
    // Leave a directory mountpoint reusable rather than dangling.
    clear_dangling_directory_mountpoint(mountpoint);
    debug!(mountpoint, "volume unmounted");
    UNMOUNTED.store(true, Ordering::SeqCst);
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 0);
    }
    Ok(())
}

/// Unmounts the Dokan volume at `mountpoint`, from any process.
///
/// `mountpoint` is a drive letter (e.g. `"Z:"`) or the directory the volume
/// was mounted on.  This removes the mount point the same way `dokanctl /u`
/// does, which stops a running [`mount`] — its call returns — and then
/// waits for the driver to release the volume.  A directory mountpoint is
/// restored to an ordinary empty directory afterwards, including one left
/// dangling by a mount process that was killed.
///
/// # Errors
///
/// Returns an error if `mountpoint` is not valid UTF-16, or if there was
/// nothing to do: the driver has no volume mounted there and the path is
/// not a mountpoint left over from one.
pub fn unmount(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wide_path = U16CString::from_str(mountpoint)?;

    dokan::init();
    let removed = remove_mount_point(&wide_path, mountpoint);
    dokan::shutdown();
    debug!(
        mountpoint,
        removed, "asked the driver to remove the mount point"
    );

    if removed {
        // Removal is asynchronous: wait for the volume to actually go, so
        // the mountpoint below is inspected in its final state.
        let deadline = Instant::now() + UNMOUNT_RELEASE_TIMEOUT;
        while is_mounted(mountpoint) && Instant::now() < deadline {
            std::thread::sleep(RETRY_POLL);
        }
    }

    let cleared = clear_dangling_directory_mountpoint(mountpoint);
    if removed || cleared {
        return Ok(());
    }
    Err(format!("no Dokan volume is mounted at {mountpoint}").into())
}

/// Asks the driver to remove `mountpoint`, retrying briefly while a volume
/// is still mounted there.
///
/// Dokan registers a directory mountpoint a moment after the volume itself
/// becomes reachable, so a removal issued immediately after a mount can be
/// rejected once or twice before it is accepted.  A mountpoint with
/// nothing mounted on it fails straight away instead of retrying.
fn remove_mount_point(wide_path: &U16CStr, mountpoint: &str) -> bool {
    let deadline = Instant::now() + UNMOUNT_RETRY_WINDOW;
    loop {
        if dokan::unmount(wide_path) {
            return true;
        }
        if !is_mounted(mountpoint) || Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(RETRY_POLL);
    }
}

/// Restores a directory mountpoint that no longer has a volume behind it,
/// reporting whether it cleaned anything up.
///
/// Dokan attaches a reparse point to a directory it mounts on and can
/// leave it behind — always when the mount process was killed, and on some
/// releases even after an orderly unmount.  What remains dangles: every
/// access to the directory fails with "a device which does not exist was
/// specified", so nothing can use the path again.  Removing the dangling
/// reparse point (which never touches the filesystem that was mounted
/// there) and recreating the directory empty makes the mountpoint usable
/// once more.
///
/// Does nothing unless the path really is an unreadable reparse point, so
/// a live mountpoint or an ordinary directory is left exactly as it is.
fn clear_dangling_directory_mountpoint(mountpoint: &str) -> bool {
    use std::os::windows::fs::MetadataExt;

    if drive_letter_root(mountpoint).is_some() {
        return false;
    }
    let dangling = std::fs::symlink_metadata(mountpoint)
        .is_ok_and(|meta| meta.file_attributes() & MOUNTPOINT_ATTRIBUTES == MOUNTPOINT_ATTRIBUTES)
        && std::fs::read_dir(mountpoint).is_err();
    if !dangling {
        return false;
    }
    debug!(mountpoint, "clearing a stale directory mountpoint");
    if std::fs::remove_dir(mountpoint).is_err() {
        debug!(mountpoint, "the stale mountpoint could not be removed");
        return false;
    }
    let _ = std::fs::create_dir(mountpoint);
    true
}

/// Whether a Dokan volume is mounted at `mountpoint` and usable.
///
/// For a drive-letter mountpoint (`"Z:"`) this is whether the volume root
/// can be opened.  A directory mountpoint has to carry both the reparse
/// point Dokan attaches to it and a readable volume behind that reparse
/// point: a mount process killed with `taskkill /F` leaves the reparse
/// point in place but nothing behind it, and such a stale mountpoint
/// answers `false` here until [`unmount`] clears it.
#[must_use]
pub fn is_mounted(mountpoint: &str) -> bool {
    use std::os::windows::fs::MetadataExt;

    if let Some(root) = drive_letter_root(mountpoint) {
        return std::fs::metadata(root).is_ok();
    }
    // `symlink_metadata` reports the directory itself, `metadata` follows
    // the reparse point into the mounted volume.
    std::fs::symlink_metadata(mountpoint)
        .is_ok_and(|meta| meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        && std::fs::metadata(mountpoint).is_ok()
}

/// The volume root (`Z:\`) of a drive-letter mountpoint, or `None` when
/// `mountpoint` is a directory path.
fn drive_letter_root(mountpoint: &str) -> Option<String> {
    let mut chars = mountpoint.trim_end_matches(['\\', '/']).chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next()? != ':' || chars.next().is_some() {
        return None;
    }
    Some(format!("{letter}:\\"))
}

/// State associated with a single open file or directory.
struct FileHandle {
    path: String,
}

/// Wraps a [`TargetFilesystem`] behind a [`Mutex`] so Dokan's
/// multi-threaded callbacks can safely access it.
struct DokanFs {
    fs: Mutex<Box<dyn TargetFilesystem>>,
    fsname: String,
    volname: String,
    total_bytes: u64,
    free_bytes: u64,
}

impl DokanFs {
    fn new(
        mut fs: Box<dyn TargetFilesystem>,
        fsname: String,
        volname: String,
        partition_bytes: u64,
    ) -> Self {
        // Use the caller-provided partition size as the total if available,
        // otherwise fall back to the filesystem's reported size.
        let total_bytes = if partition_bytes > 0 {
            partition_bytes
        } else {
            fs.total_size().unwrap_or(0)
        };

        // Query free space from the filesystem (may involve reading the
        // allocation bitmap). Falls back to the full volume size.
        let free_bytes = fs.free_space().unwrap_or(total_bytes);

        Self {
            fs: Mutex::new(fs),
            fsname,
            volname,
            total_bytes,
            free_bytes,
        }
    }
}

/// Converts a Dokan wide-string path (`\foo\bar`) to the internal
/// forward-slash representation (`foo/bar`) expected by
/// [`TargetFilesystem`].
fn to_internal_path(name: &U16CStr) -> String {
    let s = name.to_string_lossy();
    s.trim_start_matches('\\').replace('\\', "/")
}

/// Translates [`FsMetadata`] flags into Win32 `FILE_ATTRIBUTE_*` bits.
///
/// `FILE_ATTRIBUTE_READONLY` is always set because the volume is mounted
/// write-protected.
///
/// `FILE_ATTRIBUTE_SYSTEM` is intentionally **not** reported even when the
/// on-disk attribute is set.  Explorer hides `HIDDEN | SYSTEM` files unless
/// the user disables "Hide protected operating system files", which defeats
/// the purpose of a mount where everything should be visible.  The `system`
/// flag is still recorded in [`FsMetadata`] for programmatic access.
fn meta_to_attributes(m: &FsMetadata) -> u32 {
    let mut attrs = 0u32;
    if m.is_dir {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }

    if m.hidden {
        attrs |= FILE_ATTRIBUTE_HIDDEN;
    }

    // Read-only mount — always set regardless of the on-disk flag.
    attrs |= FILE_ATTRIBUTE_READONLY;

    // FILE_ATTRIBUTE_NORMAL is only valid when no other content attributes
    // are set (MSDN: "valid only if used alone").  DIRECTORY and READONLY
    // don't count as content attributes for this purpose.
    let content = attrs & !(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY);
    if content == 0 && !m.is_dir {
        attrs |= FILE_ATTRIBUTE_NORMAL;
    }

    attrs
}

/// Builds a Dokan [`FileInfo`] from [`FsMetadata`].
fn meta_to_file_info(m: &FsMetadata) -> FileInfo {
    FileInfo {
        attributes: meta_to_attributes(m),
        creation_time: to_system_time(m.created),
        last_access_time: to_system_time(m.accessed),
        last_write_time: to_system_time(m.modified),
        file_size: m.size,
        number_of_links: 1,
        file_index: 0,
    }
}

/// Returns a [`FileInfo`] for the synthetic root directory.
fn root_file_info() -> FileInfo {
    let epoch = SystemTime::UNIX_EPOCH;
    FileInfo {
        attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY,
        creation_time: epoch,
        last_access_time: epoch,
        last_write_time: epoch,
        file_size: 0,
        number_of_links: 1,
        file_index: 0,
    }
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for DokanFs {
    type Context = FileHandle;

    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        _info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        // Reject any open that implies writing or deletion.
        match create_disposition {
            FILE_SUPERSEDE | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                return Err(STATUS_ACCESS_DENIED);
            }
            _ => {}
        }
        if create_options & FILE_DELETE_ON_CLOSE != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }

        let path = to_internal_path(file_name);
        trace!(path = %path, "create or open");

        if path.is_empty() {
            return Ok(CreateFileInfo {
                context: FileHandle { path },
                is_dir: true,
                new_file_created: false,
            });
        }

        let mut fs = self.fs.lock().unwrap();
        let meta = fs
            .metadata(&path)
            .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

        Ok(CreateFileInfo {
            context: FileHandle { path },
            is_dir: meta.is_dir,
            new_file_created: false,
        })
    }

    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        let offset = u64::try_from(offset).map_err(|_| STATUS_UNSUCCESSFUL)?;
        trace!(path = %context.path, offset, len = buffer.len(), "read");
        let count = {
            let mut fs = self.fs.lock().unwrap();
            fs.read_at(&context.path, offset, buffer).map_err(|error| {
                warn!(
                    path = %context.path,
                    offset,
                    error = %error,
                    "failed to read from the mounted volume"
                );
                STATUS_UNSUCCESSFUL
            })?
        };
        u32::try_from(count).map_err(|_| STATUS_UNSUCCESSFUL)
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        trace!(path = %context.path, "file information");
        if context.path.is_empty() {
            return Ok(root_file_info());
        }
        let mut fs = self.fs.lock().unwrap();
        let meta = fs
            .metadata(&context.path)
            .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(meta_to_file_info(&meta))
    }

    fn find_files(
        &'h self,
        file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        let path = to_internal_path(file_name);
        trace!(path = %path, "list directory");
        let mut fs = self.fs.lock().unwrap();
        let entries = fs.read_dir(&path).map_err(|error| {
            warn!(
                path = %path,
                error = %error,
                "failed to list the contents of a directory"
            );
            STATUS_UNSUCCESSFUL
        })?;
        let visible = filter_entries(&entries);

        for entry in &visible {
            let m = &entry.metadata;

            let _ = fill_find_data(&FindData {
                attributes: meta_to_attributes(m),
                creation_time: to_system_time(m.created),
                last_access_time: to_system_time(m.accessed),
                last_write_time: to_system_time(m.modified),
                file_size: m.size,
                file_name: U16CString::from_str(&entry.name).unwrap_or_default(),
            });
        }
        Ok(())
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        Ok(DiskSpaceInfo {
            byte_count: self.total_bytes,
            free_byte_count: self.free_bytes,
            available_byte_count: self.free_bytes,
        })
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<VolumeInfo> {
        Ok(VolumeInfo {
            name: U16CString::from_str(&self.volname).unwrap_or_default(),
            serial_number: 0,
            max_component_length: 255,
            fs_flags: 0,
            fs_name: U16CString::from_str(&self.fsname).unwrap_or_default(),
        })
    }

    // ── Read-only: reject all mutation operations ──────────────

    fn cleanup(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
        // Nothing to clean up — the volume is read-only so no pending
        // deletes or writes need to be flushed.
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
    }

    fn write_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _buffer: &[u8],
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<u32> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_attributes(
        &'h self,
        _file_name: &U16CStr,
        _file_attributes: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_time(
        &'h self,
        _file_name: &U16CStr,
        _creation_time: FileTimeOperation,
        _last_access_time: FileTimeOperation,
        _last_write_time: FileTimeOperation,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn delete_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn delete_directory(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn move_file(
        &'h self,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_end_of_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_allocation_size(
        &'h self,
        _file_name: &U16CStr,
        _alloc_size: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_security(
        &'h self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
        _buffer_length: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
}

#[cfg(test)]
mod tests {
    use super::drive_letter_root;

    #[test]
    fn drive_letter_mountpoints_resolve_to_their_volume_root() {
        assert_eq!(drive_letter_root("Z:").as_deref(), Some("Z:\\"));
        assert_eq!(drive_letter_root("z:\\").as_deref(), Some("z:\\"));
        assert_eq!(drive_letter_root("Z:/").as_deref(), Some("Z:\\"));
    }

    #[test]
    fn directory_mountpoints_have_no_volume_root() {
        assert_eq!(drive_letter_root(r"C:\mnt\evidence"), None);
        assert_eq!(drive_letter_root("mnt"), None);
        assert_eq!(drive_letter_root(""), None);
    }
}
