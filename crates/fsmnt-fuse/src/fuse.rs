//! FUSE backend for macOS and Linux.
//!
//! Presents a [`TargetFilesystem`] as a read-only FUSE volume via the
//! [`fuser`] crate.  The volume is mounted at a regular directory path.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

use fsmnt_core::{FsMetadata, TargetFilesystem, filter_entries};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};
use tracing::{debug, trace, warn};

/// Convert `Option<DateTime<Utc>>` to [`SystemTime`], falling back to the
/// Unix epoch when `None`.
fn to_system_time(dt: Option<DateTime<Utc>>) -> SystemTime {
    dt.map_or(UNIX_EPOCH, SystemTime::from)
}

/// Attribute cache TTL.  Nothing changes on a read-only volume so we cache
/// for a long time.
const ATTR_TTL: Duration = Duration::from_hours(1);

/// Inode number of the root directory.
const ROOT_INO: u64 = 1;

/// How often the mount loop re-checks whether the volume is still mounted.
const LIVENESS_POLL: Duration = Duration::from_millis(200);

/// Mounts `fs` as a read-only FUSE volume at `mountpoint`.
///
/// Calls `on_mount` once the volume is mounted, then blocks the calling
/// thread until either
///
/// - a termination signal arrives — `SIGINT` (Ctrl+C), `SIGTERM`, or
///   `SIGHUP`, all handled through `ctrlc`'s `termination` feature — after
///   which the session is dropped, which unmounts the volume; or
/// - the volume is unmounted from elsewhere ([`unmount`], `fusermount -u`,
///   `umount`), which [`is_mounted`] detects.
///
/// Either way the volume is unmounted by the time this returns.
///
/// # Errors
///
/// Returns an error if the FUSE session cannot be created (e.g. the
/// mountpoint does not exist or FUSE is unavailable) or the signal
/// handler cannot be installed.
pub fn mount(
    fs: Box<dyn TargetFilesystem>,
    mountpoint: &str,
    fsname: &str,
    volname: &str,
    _total_bytes: u64,
    on_mount: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    let fuse_fs = FuseFs::new(fs);
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(fsname.to_string()),
        MountOption::CUSTOM("local".to_string()),
        MountOption::CUSTOM(format!("volname={volname}")),
    ];

    let session = fuser::spawn_mount2(fuse_fs, mountpoint, &config)?;
    debug!(mountpoint, fsname, volname, "volume mounted");

    on_mount();

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;

    loop {
        match rx.recv_timeout(LIVENESS_POLL) {
            // A termination signal arrived.
            Ok(()) => {
                debug!(mountpoint, "termination signal received, unmounting");
                break;
            }
            // Waking up regularly means an unmount from outside this
            // process ends the mount too, instead of leaving it blocked
            // on a signal that will never come.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !is_mounted(mountpoint) {
                    debug!(mountpoint, "volume unmounted from outside this process");
                    break;
                }
            }
            // No signal can arrive any more; keep watching the volume.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if !is_mounted(mountpoint) {
                    debug!(mountpoint, "volume unmounted from outside this process");
                    break;
                }
                std::thread::sleep(LIVENESS_POLL);
            }
        }
    }

    // Dropping the session unmounts the volume (and is a no-op once it has
    // been unmounted from elsewhere).
    drop(session);
    debug!(mountpoint, "volume unmounted");
    Ok(())
}

/// Unmount helper commands to try in order, each run as
/// `program [args…] <mountpoint>`.
///
/// `fusermount3` is the standard Linux helper, and the one `fuser`'s own
/// pure-Rust mount uses to attach the volume in the first place, so it is
/// already a run-time requirement of this crate.  The FUSE 2 helper and
/// plain `umount` are fallbacks for hosts without it.
#[cfg(target_os = "linux")]
const UNMOUNT_HELPERS: &[&[&str]] = &[&["fusermount3", "-u"], &["fusermount", "-u"], &["umount"]];

/// Unmount helper commands to try in order, each run as
/// `program [args…] <mountpoint>`.
///
/// macOS releases a `macFUSE` volume with `umount`; `diskutil unmount` is
/// the fallback, as it can also detach a volume the Finder keeps busy.
#[cfg(target_os = "macos")]
const UNMOUNT_HELPERS: &[&[&str]] = &[&["umount"], &["diskutil", "unmount"]];

/// Unmount helper commands to try in order, each run as
/// `program [args…] <mountpoint>`.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const UNMOUNT_HELPERS: &[&[&str]] = &[&["umount"]];

/// Unmounts the FUSE volume at the directory `mountpoint`, from any
/// process.
///
/// Runs the platform's unmount helper (see [`UNMOUNT_HELPERS`]), trying the
/// next one whenever a helper is missing or fails.  A [`mount`] blocked on
/// that mountpoint returns once the volume is gone.
///
/// # Errors
///
/// Returns an error if every helper failed, quoting what each of them
/// reported — typically that nothing is mounted at `mountpoint`, or that
/// the volume is busy.
pub fn unmount(mountpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::with_capacity(UNMOUNT_HELPERS.len());

    for helper in UNMOUNT_HELPERS {
        let Some((program, args)) = helper.split_first() else {
            continue;
        };
        match std::process::Command::new(program)
            .args(args)
            .arg(mountpoint)
            .output()
        {
            Ok(output) if output.status.success() => {
                debug!(mountpoint, helper = %program, "unmounted");
                return Ok(());
            }
            Ok(output) => {
                let failure = helper_failure(&output);
                debug!(helper = %program, error = %failure, "unmount helper failed");
                failures.push(format!("{program}: {failure}"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                debug!(helper = %program, "unmount helper is not installed");
                failures.push(format!("{program}: not installed"));
            }
            Err(error) => {
                debug!(helper = %program, error = %error, "unmount helper could not be run");
                failures.push(format!("{program}: {error}"));
            }
        }
    }

    Err(format!("failed to unmount {mountpoint} ({})", failures.join("; ")).into())
}

/// Describes why an unmount helper failed, preferring its own message.
fn helper_failure(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    if message.is_empty() {
        output.status.to_string()
    } else {
        message.to_string()
    }
}

/// Whether a filesystem is currently mounted at `mountpoint`.
///
/// A mountpoint carries a different device number than the directory it
/// lives in exactly while something is mounted on it, which is what this
/// compares.  When the parent directory cannot be inspected the answer is
/// `true`, so a caller waiting for an unmount keeps waiting rather than
/// giving up on an unreadable path.
#[must_use]
pub fn is_mounted(mountpoint: &str) -> bool {
    use std::os::unix::fs::MetadataExt;

    let path = std::path::Path::new(mountpoint);
    let Ok(mounted) = std::fs::metadata(path) else {
        return false;
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    match std::fs::metadata(parent) {
        Ok(parent) => parent.dev() != mounted.dev(),
        Err(_) => true,
    }
}

/// Bidirectional inode ↔ path mapping.
///
/// FUSE identifies every file by a numeric inode.  Since
/// [`TargetFilesystem`] uses string paths we maintain a translation table
/// that allocates a fresh inode for each `(parent, name)` pair on first
/// lookup.
struct InodeTable {
    by_ino: HashMap<u64, String>,
    by_name: HashMap<(u64, String), u64>,
    next_ino: u64,
}

impl InodeTable {
    fn new() -> Self {
        let mut t = Self {
            by_ino: HashMap::new(),
            by_name: HashMap::new(),
            next_ino: ROOT_INO + 1,
        };
        t.by_ino.insert(ROOT_INO, String::new());
        t
    }

    /// Returns the inode for `name` under `parent`, allocating one if this
    /// is the first time the pair is seen.
    fn lookup_or_insert(&mut self, parent: u64, name: &str) -> u64 {
        let key = (parent, name.to_string());
        if let Some(&i) = self.by_name.get(&key) {
            return i;
        }
        let i = self.next_ino;
        self.next_ino += 1;
        let parent_path = self.by_ino.get(&parent).cloned().unwrap_or_default();
        let path = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{parent_path}/{name}")
        };
        self.by_ino.insert(i, path);
        self.by_name.insert(key, i);
        i
    }

    /// Returns the path for `inode`, if known.
    fn path(&self, inode: u64) -> Option<&str> {
        self.by_ino.get(&inode).map(String::as_str)
    }
}

/// All mutable state needed by the FUSE callbacks.
///
/// Grouped into a single struct so it can be protected by one [`Mutex`]
/// inside [`FuseFs`].
struct FuseState {
    fs: Box<dyn TargetFilesystem>,
    inodes: InodeTable,
}

/// FUSE filesystem backed by a [`TargetFilesystem`].
struct FuseFs {
    state: Mutex<FuseState>,
}

impl FuseFs {
    fn new(fs: Box<dyn TargetFilesystem>) -> Self {
        Self {
            state: Mutex::new(FuseState {
                fs,
                inodes: InodeTable::new(),
            }),
        }
    }
}

fn ino(v: u64) -> fuser::INodeNo {
    fuser::INodeNo(v)
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getgid() }
}

/// Builds a FUSE [`FileAttr`] from [`FsMetadata`].
fn meta_to_attr(inode: u64, m: &FsMetadata) -> FileAttr {
    let kind = if m.is_dir {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    FileAttr {
        ino: ino(inode),
        size: m.size,
        blocks: m.size.div_ceil(512),
        atime: to_system_time(m.accessed),
        mtime: to_system_time(m.modified),
        ctime: to_system_time(m.modified),
        crtime: to_system_time(m.created),
        kind,
        perm: if m.is_dir { 0o555 } else { 0o444 },
        nlink: if m.is_dir { 2 } else { 1 },
        uid: current_uid(),
        gid: current_gid(),
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

/// Returns a [`FileAttr`] for the synthetic root directory.
fn root_attr() -> FileAttr {
    FileAttr {
        ino: ino(ROOT_INO),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o555,
        nlink: 2,
        uid: current_uid(),
        gid: current_gid(),
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

impl Filesystem for FuseFs {
    fn lookup(&self, _req: &Request, parent: fuser::INodeNo, name: &OsStr, reply: ReplyEntry) {
        trace!(parent = parent.0, name = %name.to_string_lossy(), "look up entry");
        let Some(name_str) = name.to_str() else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let mut g = self.state.lock().unwrap();
        let i = g.inodes.lookup_or_insert(parent.0, name_str);
        let path = g.inodes.path(i).unwrap().to_string();
        match g.fs.metadata(&path) {
            Ok(meta) => reply.entry(&ATTR_TTL, &meta_to_attr(i, &meta), fuser::Generation(0)),
            Err(_) => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(
        &self,
        _req: &Request,
        i: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: ReplyAttr,
    ) {
        trace!(ino = i.0, "file attributes");
        if i.0 == ROOT_INO {
            reply.attr(&ATTR_TTL, &root_attr());
            return;
        }
        let mut g = self.state.lock().unwrap();
        let Some(path) = g.inodes.path(i.0).map(String::from) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        match g.fs.metadata(&path) {
            Ok(meta) => reply.attr(&ATTR_TTL, &meta_to_attr(i.0, &meta)),
            Err(_) => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, _i: fuser::INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
    }

    fn opendir(
        &self,
        _req: &Request,
        _i: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: ReplyOpen,
    ) {
        reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        i: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        trace!(ino = i.0, offset, len = size, "read");
        let mut g = self.state.lock().unwrap();
        let Some(path) = g.inodes.path(i.0).map(String::from) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let Ok(requested) = usize::try_from(size) else {
            reply.error(fuser::Errno::EOVERFLOW);
            return;
        };
        let mut data = Vec::new();
        if data.try_reserve_exact(requested).is_err() {
            reply.error(fuser::Errno::ENOMEM);
            return;
        }
        data.resize(requested, 0);
        let read = g.fs.read_at(&path, offset, &mut data).inspect_err(|error| {
            warn!(
                path = %path,
                offset,
                error = %error,
                "failed to read from the mounted volume"
            );
        });
        let Ok(count) = read else {
            reply.error(fuser::Errno::EIO);
            return;
        };
        let Some(data) = data.get(..count) else {
            warn!(path = %path, offset, "a read reported more bytes than the buffer holds");
            reply.error(fuser::Errno::EIO);
            return;
        };
        reply.data(data);
    }

    fn readdir(
        &self,
        _req: &Request,
        i: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        trace!(ino = i.0, offset, "list directory");
        let mut g = self.state.lock().unwrap();
        let Some(path) = g.inodes.path(i.0).map(String::from) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let listed = g.fs.read_dir(&path).inspect_err(|error| {
            warn!(
                path = %path,
                error = %error,
                "failed to list the contents of a directory"
            );
        });
        let Ok(entries) = listed else {
            reply.error(fuser::Errno::EIO);
            return;
        };

        let mut all: Vec<(String, u64, FileType)> = Vec::with_capacity(entries.len() + 2);
        all.push((".".into(), i.0, FileType::Directory));
        all.push((
            "..".into(),
            if i.0 == ROOT_INO { ROOT_INO } else { i.0 },
            FileType::Directory,
        ));
        for e in filter_entries(&entries) {
            let ci = g.inodes.lookup_or_insert(i.0, &e.name);
            let kind = if e.metadata.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            all.push((e.name.clone(), ci, kind));
        }

        let skip = usize::try_from(offset).unwrap_or(usize::MAX);
        for (idx, (name, child_ino, kind)) in all.iter().enumerate().skip(skip) {
            let next_offset = u64::try_from(idx).unwrap_or(u64::MAX).saturating_add(1);
            if reply.add(ino(*child_ino), next_offset, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _i: fuser::INodeNo, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn access(
        &self,
        _req: &Request,
        _i: fuser::INodeNo,
        _mask: fuser::AccessFlags,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    use super::helper_failure;

    /// A failed helper run: `0x100` is the wait status of exit code 1.
    fn failed_run(stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(0x100),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_failure_is_described_by_the_helpers_own_message() {
        let failure = failed_run("fusermount3: entry for /mnt/evidence not found in /etc/mtab\n");
        assert_eq!(
            helper_failure(&failure),
            "fusermount3: entry for /mnt/evidence not found in /etc/mtab"
        );
    }

    #[test]
    fn a_silent_failure_falls_back_to_the_exit_status() {
        let failure = helper_failure(&failed_run("   \n"));
        assert!(failure.contains('1'), "unexpected description: {failure}");
    }
}
