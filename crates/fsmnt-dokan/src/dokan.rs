//! Dokan backend for Windows.
//!
//! Presents a [`TargetFilesystem`] as a read-only Windows volume via
//! [Dokan](https://dokan-dev.github.io/).  The volume can be mounted to a
//! drive letter (e.g. `Z:`) or an empty NTFS directory.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Utc};

use fsmnt_core::{FsError, FsMetadata, OpenedTarget, TargetFilesystem, filter_entries};

use dokan::{
    CreateDisposition, CreateFileInfo, CreateFileRequest, CreateOptions, DirectoryFiller,
    DiskSpaceInfo, FileAttributes, FileInfo, FileSystemHandler, FileSystemMounter,
    FileTimeOperation, FindData, MountFlags, MountOptions, OperationInfo, OperationResult,
    SecurityInformation, VolumeFeatures, VolumeInfo,
    status::{
        STATUS_ACCESS_DENIED, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
        STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_UNSUCCESSFUL,
    },
};
use tracing::{debug, trace, warn};
use widestring::{U16CStr, U16CString};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY as RAW_FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT as RAW_FILE_ATTRIBUTE_REPARSE_POINT,
    },
    System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    },
};

use crate::cache::{CachedMetadata, MetadataCache};

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
const MOUNTPOINT_ATTRIBUTES: u32 = RAW_FILE_ATTRIBUTE_DIRECTORY | RAW_FILE_ATTRIBUTE_REPARSE_POINT;

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
/// Returns an error if the mountpoint or volume names contain an embedded
/// null, the Dokan driver is not installed, or the volume cannot be mounted.
pub fn mount(
    fs: Box<dyn TargetFilesystem>,
    mountpoint: &str,
    fsname: &str,
    volname: &str,
    total_bytes: u64,
    on_mount: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    let wide_path = U16CString::from_str(mountpoint)?;
    if fsname.contains('\0') || volname.contains('\0') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "filesystem and volume names cannot contain null characters",
        )
        .into());
    }

    let handler = DokanFs::new(fs, fsname.into(), volname.into(), total_bytes);
    let options = MountOptions {
        flags: MountFlags::WRITE_PROTECT,
        ..Default::default()
    };

    let mounter = FileSystemMounter::new(handler, &wide_path, options);
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
        .is_ok_and(|meta| meta.file_attributes() & RAW_FILE_ATTRIBUTE_REPARSE_POINT != 0)
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
    path: Box<str>,
    file_info: FileInfo,
    target: Mutex<Option<OpenedTarget>>,
}

impl FileHandle {
    fn file_info(&self) -> FileInfo {
        self.file_info.clone()
    }
}

/// Wraps a [`TargetFilesystem`] behind a [`Mutex`] so Dokan's
/// multi-threaded callbacks can safely access it.
struct DokanFs {
    fs: Mutex<Box<dyn TargetFilesystem>>,
    metadata: Mutex<MetadataCache>,
    filesystem_name: Box<str>,
    volume_name: Box<str>,
    total_bytes: u64,
    free_bytes: u64,
}

impl DokanFs {
    fn new(
        mut fs: Box<dyn TargetFilesystem>,
        filesystem_name: Box<str>,
        volume_name: Box<str>,
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
            metadata: Mutex::new(MetadataCache::new()),
            filesystem_name,
            volume_name,
            total_bytes,
            free_bytes,
        }
    }

    /// Open `path`, reusing metadata learned from a directory listing when
    /// possible and deferring parser state until an operation needs it.
    fn open_path(&self, path: Box<str>) -> OperationResult<CreateFileInfo<FileHandle>> {
        match self.metadata.lock().unwrap().get(&path) {
            Some(CachedMetadata::Found(metadata)) => {
                return Ok(create_file_info(path, &metadata, None));
            }
            Some(CachedMetadata::Missing) => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            None => {}
        }

        let target = self.resolve_target(&path)?;
        let metadata = target.metadata().clone();
        Ok(create_file_info(path, &metadata, Some(target)))
    }

    /// Resolve a target through the parser and record the immutable result.
    fn resolve_target(&self, path: &str) -> OperationResult<OpenedTarget> {
        let result = {
            let mut fs = self.fs.lock().unwrap();
            fs.open(path)
        };
        match result {
            Ok(target) => {
                self.metadata
                    .lock()
                    .unwrap()
                    .insert_found(path, target.metadata().clone());
                Ok(target)
            }
            Err(error) => {
                if matches!(&error, FsError::NotFound(_)) {
                    self.metadata.lock().unwrap().insert_missing(path);
                }
                Err(open_error_status(path, error))
            }
        }
    }

    /// Materialize parser state for a handle created from cached metadata.
    fn ensure_target<'target>(
        &self,
        path: &str,
        target: &'target mut Option<OpenedTarget>,
    ) -> OperationResult<&'target mut OpenedTarget> {
        if target.is_none() {
            *target = Some(self.resolve_target(path)?);
        }
        target.as_mut().ok_or(STATUS_UNSUCCESSFUL)
    }

    /// Seed child metadata from the listing that already supplied it.
    fn cache_directory_entries<'a>(
        &self,
        parent: &str,
        entries: impl IntoIterator<Item = &'a fsmnt_core::FsEntry>,
    ) {
        let mut cache = self.metadata.lock().unwrap();
        for entry in entries {
            let path = if parent.is_empty() {
                entry.name.clone()
            } else {
                format!("{parent}/{}", entry.name)
            };
            cache.insert_found(&path, entry.metadata.clone());
        }
    }

    /// Enumerate the listing cached on an open directory directly into
    /// Dokany's output buffer.
    fn fill_directory(
        &self,
        context: &FileHandle,
        filler: &mut DirectoryFiller<'_>,
    ) -> OperationResult<()> {
        let mut target = context.target.lock().unwrap();
        let OpenedTarget::Directory(directory) = self.ensure_target(&context.path, &mut target)?
        else {
            return Err(STATUS_UNSUCCESSFUL);
        };
        let mut fs = self.fs.lock().unwrap();
        let entries = fs.opened_directory_entries(directory).map_err(|error| {
            warn!(
                path = %context.path,
                error = %error,
                "failed to list the contents of a directory"
            );
            STATUS_UNSUCCESSFUL
        })?;
        drop(fs);

        let visible = filter_entries(entries).collect::<Vec<_>>();
        self.cache_directory_entries(&context.path, visible.iter().copied());
        for entry in visible {
            let metadata = &entry.metadata;
            let data = FindData {
                attributes: meta_to_attributes(metadata),
                creation_time: to_system_time(metadata.created),
                last_access_time: to_system_time(metadata.accessed),
                last_write_time: to_system_time(metadata.modified),
                file_size: metadata.size,
                file_name: entry.name.as_str().into(),
            };
            match filler.push(&data) {
                Ok(status) if status.is_full() => break,
                Ok(_) => {}
                Err(error) => {
                    warn!(name = %entry.name, %error, "could not return a directory entry");
                }
            }
        }
        Ok(())
    }
}

/// Build a Dokan handle around known metadata and optional parser state.
fn create_file_info(
    path: Box<str>,
    metadata: &FsMetadata,
    target: Option<OpenedTarget>,
) -> CreateFileInfo<FileHandle> {
    let is_dir = metadata.is_dir;
    CreateFileInfo {
        context: FileHandle {
            path,
            file_info: meta_to_file_info(metadata),
            target: Mutex::new(target),
        },
        is_dir,
        new_file_created: false,
    }
}

/// Translate normal namespace lookup outcomes without logging them as
/// backend failures.
fn open_error_status(path: &str, error: FsError) -> dokan::NtStatus {
    match error {
        FsError::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::NotADirectory(_) => STATUS_NOT_A_DIRECTORY,
        FsError::NotAFile(_) => STATUS_FILE_IS_A_DIRECTORY,
        FsError::PermissionDenied(_) => STATUS_ACCESS_DENIED,
        FsError::InvalidPath(_) => STATUS_OBJECT_NAME_INVALID,
        error => {
            warn!(%path, %error, "failed to open a filesystem target");
            STATUS_UNSUCCESSFUL
        }
    }
}

/// Converts a Dokan wide-string path (`\foo\bar`) to the internal
/// forward-slash representation (`foo/bar`) expected by
/// [`TargetFilesystem`].
fn to_internal_path(name: &U16CStr) -> Box<str> {
    let units = name.as_slice();
    let relative = units
        .iter()
        .copied()
        .skip_while(|unit| *unit == u16::from(b'\\'));
    let mut path = String::with_capacity(units.len());
    for decoded in char::decode_utf16(relative) {
        let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
        path.push(if character == '\\' { '/' } else { character });
    }
    path.into_boxed_str()
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
fn meta_to_attributes(m: &FsMetadata) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    if m.is_dir {
        attrs.insert(FileAttributes::DIRECTORY);
    }

    if m.hidden {
        attrs.insert(FileAttributes::HIDDEN);
    }

    // Read-only mount — always set regardless of the on-disk flag.
    attrs.insert(FileAttributes::READ_ONLY);

    // FILE_ATTRIBUTE_NORMAL is only valid when no other content attributes
    // are set (MSDN: "valid only if used alone").  DIRECTORY and READONLY
    // don't count as content attributes for this purpose.
    if !m.hidden && !m.is_dir {
        attrs.insert(FileAttributes::NORMAL);
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

impl FileSystemHandler for DokanFs {
    type Context = FileHandle;

    fn create_file(
        &self,
        request: &CreateFileRequest<'_, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        // Reject any open that implies writing or deletion.
        if matches!(
            request.disposition,
            CreateDisposition::Supersede
                | CreateDisposition::Create
                | CreateDisposition::Overwrite
                | CreateDisposition::OverwriteIf
        ) {
            return Err(STATUS_ACCESS_DENIED);
        }
        if request.options.contains(CreateOptions::DELETE_ON_CLOSE) {
            return Err(STATUS_ACCESS_DENIED);
        }

        let path = to_internal_path(request.path);
        trace!(path = %path, "create or open");
        self.open_path(path)
    }

    fn read_file(
        &self,
        _file_name: &U16CStr,
        offset: u64,
        buffer: &mut [u8],
        _info: &OperationInfo<'_, Self>,
        context: &Self::Context,
    ) -> OperationResult<u32> {
        trace!(path = %context.path, offset, len = buffer.len(), "read");
        let mut target = context.target.lock().unwrap();
        let OpenedTarget::File(file) = self.ensure_target(&context.path, &mut target)? else {
            return Err(STATUS_UNSUCCESSFUL);
        };
        let count = {
            let mut fs = self.fs.lock().unwrap();
            fs.read_open_file(file, offset, buffer).map_err(|error| {
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
        &self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'_, Self>,
        context: &Self::Context,
    ) -> OperationResult<FileInfo> {
        trace!(path = %context.path, "file information");
        Ok(context.file_info())
    }

    fn find_files(
        &self,
        _file_name: &U16CStr,
        filler: &mut DirectoryFiller<'_>,
        _info: &OperationInfo<'_, Self>,
        context: &Self::Context,
    ) -> OperationResult<()> {
        trace!(path = %context.path, "list directory");
        self.fill_directory(context, filler)
    }

    fn get_disk_free_space(
        &self,
        _info: &OperationInfo<'_, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        Ok(DiskSpaceInfo {
            byte_count: self.total_bytes,
            free_byte_count: self.free_bytes,
            available_byte_count: self.free_bytes,
        })
    }

    fn get_volume_information(
        &self,
        _info: &OperationInfo<'_, Self>,
    ) -> OperationResult<VolumeInfo<'_>> {
        Ok(VolumeInfo {
            name: self.volume_name.as_ref().into(),
            serial_number: 0,
            max_component_length: 255,
            features: VolumeFeatures::empty(),
            fs_name: self.filesystem_name.as_ref().into(),
        })
    }

    // ── Read-only: reject all mutation operations ──────────────

    fn write_file(
        &self,
        _file_name: &U16CStr,
        _offset: i64,
        _buffer: &[u8],
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<u32> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn flush_file_buffers(
        &self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_attributes(
        &self,
        _file_name: &U16CStr,
        _file_attributes: FileAttributes,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_time(
        &self,
        _file_name: &U16CStr,
        _creation_time: FileTimeOperation,
        _last_access_time: FileTimeOperation,
        _last_write_time: FileTimeOperation,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn delete_file(
        &self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn delete_directory(
        &self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn move_file(
        &self,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_end_of_file(
        &self,
        _file_name: &U16CStr,
        _offset: i64,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_allocation_size(
        &self,
        _file_name: &U16CStr,
        _alloc_size: i64,
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }

    fn set_file_security(
        &self,
        _file_name: &U16CStr,
        _security_information: SecurityInformation,
        _security_descriptor: &[u8],
        _info: &OperationInfo<'_, Self>,
        _context: &Self::Context,
    ) -> OperationResult<()> {
        Err(STATUS_ACCESS_DENIED)
    }
}

#[cfg(test)]
#[path = "dokan_tests.rs"]
mod tests;
