//! Dokan backend for Windows.
//!
//! Presents a [`TargetFilesystem`] as a read-only Windows volume via
//! [Dokan](https://dokan-dev.github.io/).  The volume can be mounted to a
//! drive letter (e.g. `Z:`) or an empty NTFS directory.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use chrono::{DateTime, Utc};

use fsmnt_core::{FsMetadata, TargetFilesystem, filter_entries};

use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter,
    FileTimeOperation, FillDataResult, FindData, IO_SECURITY_CONTEXT, MountFlags, MountOptions,
    OperationInfo, OperationResult, VolumeInfo,
};
use widestring::{U16CStr, U16CString};
use windows_sys::Win32::{
    Foundation::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_UNSUCCESSFUL},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_READONLY,
    },
    System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler},
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

/// Console control handler: request a clean unmount on Ctrl+C, Ctrl+Break,
/// or console close.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => {
            STOP.store(true, Ordering::SeqCst);
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
/// the calling thread until Ctrl+C.  Uses a Windows console control
/// handler directly (instead of `ctrlc`) because Dokan installs its own
/// handler that can conflict.
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

    on_mount();

    STOP.store(false, Ordering::SeqCst);
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }

    // Poll until signalled — Dokan callbacks keep running on other threads.
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = dokan::unmount(&wide_path);
    drop(file_system);
    dokan::shutdown();
    Ok(())
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
        let count = {
            let mut fs = self.fs.lock().unwrap();
            fs.read_at(&context.path, offset, buffer).map_err(|error| {
                eprintln!(
                    "fsmnt-dokan: failed to read {:?} at offset {offset}: {error}",
                    context.path
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
        let mut fs = self.fs.lock().unwrap();
        let entries = fs.read_dir(&path).map_err(|error| {
            eprintln!("fsmnt-dokan: failed to list {path:?}: {error}");
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
