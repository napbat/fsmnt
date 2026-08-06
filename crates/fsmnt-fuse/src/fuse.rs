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

/// Mounts `fs` as a read-only FUSE volume at `mountpoint`.
///
/// Calls `on_mount` once the volume is mounted, then blocks the calling
/// thread until Ctrl+C, unmounts, and returns.
///
/// # Errors
///
/// Returns an error if the FUSE session cannot be created (e.g. the
/// mountpoint does not exist or FUSE is unavailable) or the Ctrl+C
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

    let _session = fuser::spawn_mount2(fuse_fs, mountpoint, &config)?;

    on_mount();

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    let _ = rx.recv();

    Ok(())
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
    file_cache: HashMap<u64, Vec<u8>>,
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
                file_cache: HashMap::new(),
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
        let mut g = self.state.lock().unwrap();
        let Some(path) = g.inodes.path(i.0).map(String::from) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        if !g.file_cache.contains_key(&i.0) {
            let Ok(data) = g.fs.read(&path) else {
                reply.error(fuser::Errno::EIO);
                return;
            };
            g.file_cache.insert(i.0, data);
        }
        let data = g.file_cache.get(&i.0).unwrap();
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        reply.data(&data[start..end]);
    }

    fn readdir(
        &self,
        _req: &Request,
        i: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut g = self.state.lock().unwrap();
        let Some(path) = g.inodes.path(i.0).map(String::from) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let Ok(entries) = g.fs.read_dir(&path) else {
            reply.error(fuser::Errno::EIO);
            return;
        };

        let visible = filter_entries(&entries);

        let mut all: Vec<(String, u64, FileType)> = Vec::with_capacity(visible.len() + 2);
        all.push((".".into(), i.0, FileType::Directory));
        all.push((
            "..".into(),
            if i.0 == ROOT_INO { ROOT_INO } else { i.0 },
            FileType::Directory,
        ));
        for e in &visible {
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
            if reply.add(ino(*child_ino), (idx as u64) + 1, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        i: fuser::INodeNo,
        _fh: fuser::FileHandle,
        _flags: fuser::OpenFlags,
        _lock: Option<fuser::LockOwner>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let mut g = self.state.lock().unwrap();
        g.file_cache.remove(&i.0);
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
