//! ext2/ext3/ext4 adapter over the vendored `fs-ext` parser.
//!
//! [`ExtFilesystem`] exposes a raw ext volume through
//! [`TargetFilesystem`]; [`ExtDriver`] registers it for
//! [`DetectedBootSector::Ext`].
//!
//! Dirty-image recovery (journal replay, then orphan-inode processing) is
//! handled inside the adapter, so callers always receive a handle onto the
//! post-recovery filesystem state.
//!
//! Two damaged-media modes sit alongside that: [`backup`] opens a volume
//! through the metadata copy kept in a later block group when the primary
//! copy is unreadable, and [`salvage`] recovers file content by sweeping
//! the inode tables when the directory tree is not usable.

mod backup;
mod dir;
mod fscrypt;
mod salvage;

use std::io;

use chrono::{DateTime, Utc};
use fs_ext::io::{Read, Seek, SeekFrom};
use fs_ext::{Ext, ExtError, ExtTimestamp, JournalReplay, OrphanReplay, OverlayReader};
use fsmnt_core::{FsEntry, FsError, FsMetadata, FsResult, TargetFilesystem};
use fsmnt_device::{
    DetectedBootSector, DeviceReader, FilesystemDriver, FilesystemOpenOptions, FilesystemRoot,
    FscryptKeySpec,
};
use fsmnt_parser_core::io::FsReadSeek;
use fsmnt_parser_core::traverse::EntryKind;
use tracing::debug;

use crate::adapter::{found, read_at_through, read_up_to};
use crate::identity;

/// Root inode number for ext2/ext3/ext4.
const EXT4_ROOT_INO: u32 = 2;

/// A raw ext2/ext3/ext4 volume exposed as a [`TargetFilesystem`].
///
/// Construction strict-opens the filesystem; if that reports
/// `NeedsRecovery` or `OrphanRecoveryRequired`, the canonical recovery
/// flow runs and the handle is re-opened through the resulting overlay.
pub struct ExtFilesystem<R: Read + Seek + Send> {
    reader: R,
    ext: Ext,
    overlay: Overlay,
    /// Whether the damaged-tree recovery view is active.
    salvage: bool,
    /// Sweep results, filled the first time the salvage directory is
    /// listed. Walking every inode table costs one pass over the metadata,
    /// so a mount that never opens the directory never pays for it.
    salvaged: Option<Vec<salvage::SalvagedInode>>,
    /// How the volume was opened, when that departed from a plain open —
    /// reported through [`TargetFilesystem::notices`].
    notices: Vec<String>,
}

/// What a path names inside the mounted volume.
enum Target {
    /// The mount root, which salvage mode treats specially.
    Root,
    /// An inode reached through the directory tree, or directly by number
    /// under the salvage directory.
    Inode(u32),
    /// The synthetic salvage directory itself. It has no inode: its
    /// entries are produced by sweeping the inode tables.
    SalvageRoot,
}

impl Target {
    /// The inode backing this target, or `None` for the synthetic salvage
    /// directory.
    const fn inode(&self) -> Option<u32> {
        match self {
            Self::Root => Some(EXT4_ROOT_INO),
            Self::Inode(inum) => Some(*inum),
            Self::SalvageRoot => None,
        }
    }
}

/// Which replay artifact, if any, serves overlay reads.
///
/// The [`Ext`] handle in [`ExtFilesystem`] is always strict-opened through
/// the matching overlay, so feature-flag validation reflects the
/// post-recovery state.
enum Overlay {
    /// The strict open succeeded directly; no recovery was needed.
    Clean,
    /// The caller declined replay: reads present the on-disk bytes even if
    /// the journal is dirty or orphans are pending. Serves reads exactly
    /// like [`Overlay::Clean`]; kept distinct so the choice is reportable.
    Unreplayed,
    /// Journal replay ran; no pending orphan state.
    Journal(JournalReplay),
    /// Journal *and* orphan replay ran. Transitively owns the journal.
    Orphan(OrphanReplay),
}

/// Per-call reader view.
///
/// `dyn Read + Seek` is not valid Rust, and the fs-ext APIs bound
/// `T: Read + Seek + Sized`, so a trait object would not satisfy them.
/// This concrete enum yields one monomorphization per overlay variant
/// with no dispatch cost beyond the match.
enum Reader<'fs, R: Read + Seek> {
    Direct(&'fs mut R),
    Journal(OverlayReader<'fs, 'fs, R, JournalReplay>),
    Orphan(OverlayReader<'fs, 'fs, R, OrphanReplay>),
}

impl<R: Read + Seek> Read for Reader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Reader::Direct(r) => r.read(buf),
            Reader::Journal(r) => r.read(buf),
            Reader::Orphan(r) => r.read(buf),
        }
    }
}

impl<R: Read + Seek> Seek for Reader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Reader::Direct(r) => r.seek(pos),
            Reader::Journal(r) => r.seek(pos),
            Reader::Orphan(r) => r.seek(pos),
        }
    }
}

/// Convert an [`ExtTimestamp`] to `DateTime<Utc>`, returning `None` only
/// when the value is out of range.
///
/// `(seconds = 0, nanoseconds = 0)` is a legitimate 1970-01-01T00:00:00Z
/// value on ext, not an "unset" sentinel the way it is on FAT and NTFS.
fn ts_to_utc(ts: ExtTimestamp) -> Option<DateTime<Utc>> {
    DateTime::try_from(ts).ok()
}

/// Split a forensic ext path into byte-exact components, resolving `.`
/// and `..` lexically.
///
/// Unlike [`fsmnt_core::normalize_path`], every non-`/` byte is preserved
/// verbatim: ext permits `\` and `:` in filenames, so rewriting them would
/// make those entries unopenable.
fn canonicalise_ext_path(path: &str) -> Vec<&str> {
    let stripped = path.trim_start_matches('/');
    let mut stack: Vec<&str> = Vec::new();
    for component in stripped.split('/').filter(|s| !s.is_empty()) {
        match component {
            "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    stack
}

/// Map an [`ExtError`] onto the closest [`FsError`] variant.
///
/// `NeedsRecovery` and `OrphanRecoveryRequired` never reach steady-state
/// methods — they surface only during [`ExtFilesystem::new`] and are
/// consumed by the recovery flow — but are still mapped here defensively.
/// `TimestampOutOfRange` is swallowed by [`ts_to_utc`] and surfaces as
/// `None` rather than reaching this helper.
fn map_ext_error(e: ExtError, path: &str) -> FsError {
    match e {
        ExtError::NotFound => FsError::NotFound(path.to_string()),
        ExtError::NotADirectory { .. } => FsError::NotADirectory(path.to_string()),
        ExtError::IsADirectory { .. } => FsError::NotAFile(path.to_string()),
        ExtError::Io(io_err) => FsError::Io(io_err),
        ExtError::JournalExpectedButAbsent => FsError::Filesystem(
            "filesystem requires recovery but no journal is available".to_string(),
        ),
        ExtError::EncryptedInode { inode } => {
            FsError::Filesystem(format!("inode {inode} is encrypted"))
        }
        // The one error an operator can actually do something about: it
        // names the master key the volume wants, so the message says which
        // one and how to hand it over. The mount backends turn this into
        // EIO for the caller and `warn!` the text, which is where it is
        // read.
        ExtError::MissingFscryptKey {
            inode,
            policy_kind,
            key_ref,
        } => FsError::Filesystem(crate::fscrypt::missing_key_message(
            inode,
            &policy_kind,
            &key_ref,
        )),
        ExtError::UnsupportedEaInode { inode } => {
            FsError::Filesystem(format!("inode {inode} uses EA inode references"))
        }
        other => FsError::Filesystem(format!("{other}")),
    }
}

/// Map a failure from the recovery path, naming the stage and the way out.
///
/// Everything this covers happens because the volume was dirty and replay
/// was attempted. A missing, truncated or unparsable journal is the common
/// cause, and the on-disk view is then still perfectly readable — so the
/// error says so rather than leaving the caller with a volume that simply
/// refuses to open.
fn map_replay_error(e: &ExtError, stage: &str) -> FsError {
    FsError::Filesystem(format!(
        "{stage} failed: {e}; retry with --no-journal-replay to present the on-disk state"
    ))
}

impl<R: Read + Seek + Send> ExtFilesystem<R> {
    /// Open an ext2/ext3/ext4 volume from `reader`.
    ///
    /// A dirty image is recovered automatically:
    /// 1. Strict-open first. Success → no overlay.
    /// 2. On `NeedsRecovery` / `OrphanRecoveryRequired`, build a
    ///    [`JournalReplay`] and strict-reopen through the overlay.
    /// 3. If that still reports `OrphanRecoveryRequired`, build an
    ///    [`OrphanReplay`] on top of the journal and strict-reopen through
    ///    the combined overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the superblock cannot be parsed, if recovery is
    /// required but no journal is present, or if the post-recovery strict
    /// open still fails (e.g. an unsupported incompatible feature flag).
    pub fn new(reader: R) -> FsResult<Self> {
        Self::opened(reader, true, false, &[])
    }

    /// Open an ext volume as [`Self::new`] does, registering `keys` as
    /// fscrypt master keys before any read happens.
    ///
    /// Without them an fscrypt volume still opens: the names inside
    /// encrypted directories then present in the kernel's no-key form and
    /// encrypted file contents cannot be read. Which keys the volume is
    /// asking for is reported through [`TargetFilesystem::notices`] either
    /// way.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::new`], plus a failure naming
    /// the key (by its position in `keys`) when one is not a length fscrypt
    /// accepts.
    pub fn new_with_fscrypt_keys(reader: R, keys: &[FscryptKeySpec]) -> FsResult<Self> {
        Self::opened(reader, true, false, keys)
    }

    /// The one open path: choose the view, register the keys, and describe
    /// what was done.
    ///
    /// Each public constructor is one point in this space; keeping them a
    /// single function is what guarantees that every way of opening a
    /// volume registers the operator's fscrypt keys and reports the same
    /// encryption census.
    fn opened(
        mut reader: R,
        journal_replay: bool,
        salvage: bool,
        keys: &[FscryptKeySpec],
    ) -> FsResult<Self> {
        let mut fs = if journal_replay {
            match Ext::new(&mut reader) {
                Ok(ext) => Self::from_parts(reader, ext, Overlay::Clean, keys)?,
                Err(ExtError::NeedsRecovery | ExtError::OrphanRecoveryRequired) => {
                    Self::recover(reader, keys)?
                }
                Err(e) => return Err(map_ext_error(e, "<open>")),
            }
        } else {
            let ext = Ext::open_lenient(&mut reader).map_err(|e| map_ext_error(e, "<open>"))?;
            Self::from_parts(reader, ext, Overlay::Unreplayed, keys)?
        };
        if salvage {
            fs.salvage = true;
            debug!(
                journal_replay,
                "salvage mode engaged; the root directory need not be listable"
            );
            fs.notices.push(
                "salvage mode: every in-use inode found by sweeping the inode tables is listed
                 under /.fsmnt-salvage as inode-N; the root directory is presented as empty if it
                 cannot be listed"
                    .to_string(),
            );
        } else {
            fs.check_root_directory()?;
        }
        fs.report_fscrypt();
        Ok(fs)
    }

    /// Say what this volume's encryption asks for, if it has any.
    ///
    /// Runs after the view is settled so the census reads through whatever
    /// overlay is serving the mount, and never fails: an encrypted volume
    /// is still mountable when the census cannot read part of the tree.
    fn report_fscrypt(&mut self) {
        let found = self.with_reader(fscrypt::notices);
        self.notices.extend(found);
    }

    /// Assemble a handle in the default (non-salvage) view, noting how the
    /// volume's dirty state (if any) is being presented, and registering
    /// the operator's fscrypt master keys.
    fn from_parts(
        reader: R,
        mut ext: Ext,
        overlay: Overlay,
        keys: &[FscryptKeySpec],
    ) -> FsResult<Self> {
        fscrypt::register_keys(&mut ext, keys)?;
        let mut notices = Vec::new();
        match &overlay {
            Overlay::Clean => {}
            Overlay::Journal(_) => notices.push(
                "the volume was not cleanly unmounted; its journal was replayed into an in-memory
                 overlay (nothing is written to the source) — pass --no-journal-replay for the
                 on-disk state"
                    .to_string(),
            ),
            Overlay::Orphan(_) => notices.push(
                "the volume was not cleanly unmounted; its journal and orphan list were replayed
                 into an in-memory overlay (nothing is written to the source) — pass
                 --no-journal-replay for the on-disk state"
                    .to_string(),
            ),
            Overlay::Unreplayed => {
                if ext.needs_journal_recovery() || ext.has_orphan_present() {
                    notices.push(
                        "the volume was not cleanly unmounted and replay was declined: this is the
                         on-disk state, and files touched by the pending journal or orphan list may
                         read stale"
                            .to_string(),
                    );
                }
            }
        }
        debug!(
            replay = match &overlay {
                Overlay::Clean => "not needed",
                Overlay::Unreplayed => "declined by the caller",
                Overlay::Journal(_) => "journal",
                Overlay::Orphan(_) => "journal and orphan list",
            },
            dirty = ext.needs_journal_recovery() || ext.has_orphan_present(),
            block_size = ext.block_size(),
            inode_count = ext.inode_count(),
            size_bytes = ext.size(),
            "opened an ext volume"
        );
        Ok(Self {
            reader,
            ext,
            overlay,
            salvage: false,
            salvaged: None,
            notices,
        })
    }

    /// Open an ext2/ext3/ext4 volume in **salvage** mode: recover what the
    /// metadata still reaches instead of refusing a volume whose directory
    /// tree is unusable.
    ///
    /// A superblock and group-descriptor table are still required — without
    /// them nothing can be located at all — but the root directory is not.
    /// Three things change relative to [`Self::new`]:
    ///
    /// 1. The open no longer fails when the root cannot be listed, and the
    ///    root then presents as an empty directory rather than an error.
    /// 2. A synthetic top-level directory
    ///    ([`.fsmnt-salvage`](salvage::SALVAGE_DIR)) appears, listing every
    ///    in-use inode found by sweeping the readable block groups as
    ///    `inode-<N>`.
    /// 3. Directories among those are enterable, which recovers the real
    ///    names of everything below any surviving directory.
    ///
    /// `journal_replay` selects the same view as it does for the ordinary
    /// constructors: replayed (`true`) or exactly as it sits on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the superblock or group descriptors cannot be
    /// parsed, or if requested replay fails.
    pub fn new_salvaging(reader: R, journal_replay: bool) -> FsResult<Self> {
        Self::opened(reader, journal_replay, true, &[])
    }

    /// Open an ext2/ext3/ext4 volume from `reader` **without** journal or
    /// orphan replay: reads present the bytes exactly as they sit on disk,
    /// even if the journal is dirty (`INCOMPAT_RECOVER`) or orphans are
    /// pending (`RO_COMPAT_ORPHAN_PRESENT`).
    ///
    /// [`Self::new`] never writes to the source either — replay only builds
    /// an in-memory overlay — so this is not a safety switch but a *view*
    /// switch: it lets evidence workflows compare what fsmnt presents with
    /// what a carving tool sees in the raw image, and it makes a dirty
    /// volume browsable when its journal is missing or unparsable.
    ///
    /// # Errors
    ///
    /// Returns an error if the superblock, feature flags, or group
    /// descriptors are invalid, or if the root directory is unusable.
    pub fn new_without_replay(reader: R) -> FsResult<Self> {
        Self::opened(reader, false, false, &[])
    }

    /// Fail the open unless the root directory (inode 2) is a directory
    /// whose entries can actually be listed.
    ///
    /// A superblock alone does not prove the volume is usable: the group
    /// descriptors and inode tables are located relative to the superblock,
    /// so a plausible-looking superblock that is not the primary — an ext
    /// backup copy partway into a partition, or a stale one on reused media
    /// — parses fine and then yields a mount with no readable files. A
    /// truncated image has the same shape: the inode table near the start
    /// survives while the root's data blocks are past the end. In a forensic
    /// context "mounted, empty" is easily misread as "no data"; refusing to
    /// open with a pointed message is the safer outcome, and after this
    /// check a successful mount guarantees that at least the root lists.
    ///
    /// [`Self::new_salvaging`] skips this check: recovering the files a
    /// damaged volume still holds is precisely the case this refusal
    /// otherwise blocks.
    fn check_root_directory(&mut self) -> FsResult<()> {
        // The inode borrows `ext`, so decide inside the closure and hand
        // out only an owned verdict.
        let verdict = self.with_reader(|ext, reader| {
            ext.inode(reader, EXT4_ROOT_INO)
                .map(|inode| inode.is_directory())
                .map_err(|e| e.to_string())
        });
        match verdict {
            Ok(true) => {}
            Ok(false) => {
                return Err(FsError::Filesystem(format!(
                    "root inode {EXT4_ROOT_INO} is not a directory; the superblock at this offset \
                     does not describe a usable filesystem (a backup superblock rather than the \
                     primary?)"
                )));
            }
            Err(e) => {
                return Err(FsError::Filesystem(format!(
                    "root directory (inode {EXT4_ROOT_INO}) is unreadable: {e}; the superblock at \
                     this offset does not describe a usable filesystem (a backup superblock rather \
                     than the primary?)"
                )));
            }
        }
        self.with_reader(|ext, reader| dir::list(ext, reader, EXT4_ROOT_INO, "/"))
            .map(drop)
            .map_err(|e| {
                FsError::Filesystem(format!(
                    "root directory cannot be listed: {e}; the volume is not usable from this \
                     source (truncated image, or a superblock that is not the primary?)"
                ))
            })
    }

    /// Run journal (and, if still needed, orphan) replay, then strict-open
    /// through the resulting overlay.
    fn recover(mut reader: R, keys: &[FscryptKeySpec]) -> FsResult<Self> {
        let lenient = Ext::open_lenient(&mut reader).map_err(|e| map_replay_error(&e, "open"))?;
        let journal = JournalReplay::build(&lenient, &mut reader)
            .map_err(|e| map_replay_error(&e, "journal replay"))?;

        let strict_attempt = {
            let mut or = OverlayReader::new(&mut reader, &journal);
            Ext::new(&mut or)
        };

        match strict_attempt {
            Ok(ext) => Self::from_parts(reader, ext, Overlay::Journal(journal), keys),
            Err(ExtError::OrphanRecoveryRequired) => {
                // Parse a lenient Ext through the journal overlay so the
                // orphan stage consumes the post-journal metadata snapshot.
                let post_journal_lenient = {
                    let mut or = OverlayReader::new(&mut reader, &journal);
                    Ext::open_lenient(&mut or)
                        .map_err(|e| map_replay_error(&e, "reopening after journal replay"))?
                };
                let orphan = OrphanReplay::build(journal, &post_journal_lenient, &mut reader)
                    .map_err(|e| map_replay_error(&e, "orphan replay"))?;
                let ext = {
                    let mut or = OverlayReader::new(&mut reader, &orphan);
                    Ext::new(&mut or)
                        .map_err(|e| map_replay_error(&e, "reopening after orphan replay"))?
                };
                Self::from_parts(reader, ext, Overlay::Orphan(orphan), keys)
            }
            Err(e) => Err(map_replay_error(&e, "reopening after journal replay")),
        }
    }

    /// Resolve a path to what it names.
    ///
    /// Returns [`Target::Root`] for an empty or root-only path. In salvage
    /// mode a path under [`salvage::SALVAGE_DIR`] is resolved by inode
    /// number instead of by directory lookup, and anything below that entry
    /// is then walked normally — which is what makes a surviving directory
    /// browsable under its real names.
    fn resolve(&mut self, path: &str) -> FsResult<Target> {
        let stack = canonicalise_ext_path(path);
        let Some((first, rest)) = stack.split_first() else {
            return Ok(Target::Root);
        };
        if self.salvage && *first == salvage::SALVAGE_DIR {
            let Some((entry, below)) = rest.split_first() else {
                return Ok(Target::SalvageRoot);
            };
            let inum =
                salvage::name_inode(entry).ok_or_else(|| FsError::NotFound(path.to_string()))?;
            return self.walk(inum, below, path).map(Target::Inode);
        }
        self.walk(EXT4_ROOT_INO, &stack, path).map(Target::Inode)
    }

    /// Walk `components` down from the directory inode `start`.
    fn walk(&mut self, start: u32, components: &[&str], path: &str) -> FsResult<u32> {
        if components.is_empty() {
            return Ok(start);
        }
        self.with_reader(|ext, reader| -> FsResult<u32> {
            let mut current_inum = start;
            for (idx, component) in components.iter().enumerate() {
                let mut dir = ext.directory_at(current_inum);
                let entry = match dir.lookup(reader, component.as_bytes()) {
                    Ok(entry) => entry,
                    Err(missing_key_error @ ExtError::MissingFscryptKey { .. }) => {
                        debug!(
                            inode = current_inum,
                            error = %missing_key_error,
                            "resolving an fscrypt no-key path component"
                        );
                        match dir.lookup_nokey(reader, component.as_bytes()) {
                            Ok(entry) => entry,
                            Err(ExtError::NotFound) => {
                                return Err(map_ext_error(missing_key_error, path));
                            }
                            Err(error) => return Err(map_ext_error(error, path)),
                        }
                    }
                    Err(error) => return Err(map_ext_error(error, path)),
                };
                let is_last = idx == components.len() - 1;
                if !is_last && !matches!(entry.kind, EntryKind::Directory) {
                    return Err(FsError::NotADirectory(path.to_string()));
                }
                current_inum = entry.inode_number;
            }
            Ok(current_inum)
        })
    }

    /// Resolve `path` to an inode, treating the synthetic salvage
    /// directory as "not a file" for the callers that need one.
    fn resolve_inode(&mut self, path: &str) -> FsResult<u32> {
        self.resolve(path)?
            .inode()
            .ok_or_else(|| FsError::NotAFile(path.to_string()))
    }

    /// The sweep results, running the sweep on first use.
    fn salvaged(&mut self) -> &[salvage::SalvagedInode] {
        if self.salvaged.is_none() {
            let found = self.with_reader(|ext, reader| salvage::sweep(ext, reader));
            debug!(
                inodes = found.len(),
                "swept the inode tables for salvageable inodes"
            );
            self.salvaged = Some(found);
        }
        self.salvaged.as_deref().unwrap_or_default()
    }

    /// Run `f` with a reader view that routes through the active overlay.
    fn with_reader<T>(&mut self, f: impl FnOnce(&Ext, &mut Reader<'_, R>) -> T) -> T {
        let mut reader = match &self.overlay {
            Overlay::Clean | Overlay::Unreplayed => Reader::Direct(&mut self.reader),
            Overlay::Journal(j) => Reader::Journal(OverlayReader::new(&mut self.reader, j)),
            Overlay::Orphan(o) => Reader::Orphan(OverlayReader::new(&mut self.reader, o)),
        };
        f(&self.ext, &mut reader)
    }

    /// Which recovery overlay is serving reads: `"clean"`, `"journal"` or
    /// `"orphan"`.
    ///
    /// Reported by the CLI and useful in tests to confirm a dirty image
    /// took the expected recovery path.
    #[must_use]
    pub fn overlay_kind(&self) -> &'static str {
        match &self.overlay {
            Overlay::Clean => "clean",
            Overlay::Unreplayed => "unreplayed",
            Overlay::Journal(_) => "journal",
            Overlay::Orphan(_) => "orphan",
        }
    }
}

impl<R: Read + Seek + Send> TargetFilesystem for ExtFilesystem<R> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let inum = self.resolve_inode(path)?;
        self.with_reader(|ext, reader| -> FsResult<Vec<u8>> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            // Gate on is_regular_file(), NOT merely !is_directory: a
            // symlink's target bytes must not leak through the file reader.
            if !inode.is_regular_file() {
                return Err(FsError::NotAFile(path.to_string()));
            }
            let mut file = inode.open_file().map_err(|e| map_ext_error(e, path))?;
            read_up_to(inode.size(), |buffer| {
                file.read(reader, buffer)
                    .map_err(|e| map_ext_error(e, path))
            })
        })
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let target = self.resolve(path)?;
        let Some(inum) = target.inode() else {
            return Err(FsError::NotAFile(path.to_string()));
        };
        self.with_reader(|ext, reader| -> FsResult<usize> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            if !inode.is_regular_file() {
                return Err(FsError::NotAFile(path.to_string()));
            }
            let mut file = inode.open_file().map_err(|e| map_ext_error(e, path))?;
            read_at_through(&mut file, reader, offset, buffer, |e| {
                map_ext_error(e, path)
            })
        })
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.resolve(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        let inum = match self.resolve(path) {
            Ok(target) => match target.inode() {
                Some(inum) => inum,
                // The salvage directory is synthetic but is a directory.
                None => return Ok(true),
            },
            Err(FsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.with_reader(|ext, reader| -> FsResult<bool> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            Ok(inode.is_directory())
        })
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        let inum = match self.resolve(path) {
            Ok(target) => match target.inode() {
                Some(inum) => inum,
                None => return Ok(false),
            },
            Err(FsError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.with_reader(|ext, reader| -> FsResult<bool> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            Ok(inode.is_regular_file())
        })
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let Some(inum) = self.resolve(path)?.inode() else {
            return Ok(salvage::directory_metadata());
        };
        self.with_reader(|ext, reader| -> FsResult<FsMetadata> {
            let inode = ext
                .inode(reader, inum)
                .map_err(|e| map_ext_error(e, path))?;
            let is_dir = inode.is_directory();
            Ok(FsMetadata {
                size: if is_dir { 0 } else { inode.size() },
                is_dir,
                created: inode.crtime().and_then(ts_to_utc),
                modified: ts_to_utc(inode.mtime()),
                accessed: ts_to_utc(inode.atime()),
                readonly: false,
                hidden: false,
                system: false,
            })
        })
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let target = self.resolve(path)?;
        let inum = match target {
            Target::SalvageRoot => {
                let found = salvage::listing(self.salvaged(), path);
                return Ok(found);
            }
            Target::Root => {
                let listed =
                    self.with_reader(|ext, reader| dir::list(ext, reader, EXT4_ROOT_INO, path));
                if !self.salvage {
                    return listed;
                }
                // Salvage mode is entered precisely because the tree may be
                // unusable, so an unlistable root is expected rather than
                // an error — and the salvage directory is what the caller
                // came for. A real entry of the same name would be shadowed
                // by path resolution anyway, so it is dropped rather than
                // listed twice.
                let mut entries = listed.unwrap_or_default();
                entries.retain(|entry| entry.name != salvage::SALVAGE_DIR);
                entries.push(salvage::directory_entry(path));
                return Ok(entries);
            }
            Target::Inode(inum) => inum,
        };
        self.with_reader(|ext, reader| dir::list(ext, reader, inum, path))
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.ext.size())
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(self.ext.free_bytes())
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::uuid(self.ext.uuid()))
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }
}

/// [`FilesystemDriver`] for ext2/ext3/ext4 volumes.
pub struct ExtDriver;

impl FilesystemDriver for ExtDriver {
    fn name(&self) -> &'static str {
        "ext"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ext
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(ExtFilesystem::new(reader)?))
    }

    /// ext has a single root, so only [`FilesystemRoot::Default`] is
    /// accepted. The remaining options all pick a *view* of the same
    /// bytes: [`FilesystemOpenOptions::journal_replay`] chooses between the
    /// recovered view ([`ExtFilesystem::new`]) and the raw on-disk view
    /// ([`ExtFilesystem::new_without_replay`]);
    /// [`FilesystemOpenOptions::ext_backup_superblock`] reads the metadata
    /// from a later block group's backup copy instead of the primary; and
    /// [`FilesystemOpenOptions::salvage`] opens a volume whose directory
    /// tree is unusable ([`ExtFilesystem::new_salvaging`]).
    fn open_with_options(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        if options.root() != &FilesystemRoot::Default {
            return Err(FsError::Filesystem(format!(
                "filesystem driver {:?} does not support root selector {:?}",
                self.name(),
                options.root()
            )));
        }
        let replay = options.journal_replay();
        let salvage = options.salvage();
        let keys = options.fscrypt_keys();
        match options.ext_backup_superblock() {
            Some(group) => {
                let patched = backup::patch_from_backup(reader, group)?;
                let mut fs = ExtFilesystem::opened(patched, replay, salvage, keys)?;
                fs.notices.push(format!(
                    "opened through the backup superblock (and group descriptors) of block group
                     {group}; the primary copies at the start of the volume were not used"
                ));
                Ok(Box::new(fs))
            }
            None => Ok(Box::new(ExtFilesystem::opened(
                reader, replay, salvage, keys,
            )?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_only_ext() {
        crate::test_support::assert_supports_exactly(&ExtDriver, &[DetectedBootSector::Ext]);
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(ExtDriver.name(), "ext");
    }

    #[test]
    fn opening_a_non_ext_image_fails() {
        let reader = Box::new(Cursor::new(vec![0u8; 8192]));
        assert!(
            ExtDriver.open(reader, DetectedBootSector::Ext).is_err(),
            "an all-zero image must not parse as ext"
        );
    }

    #[test]
    fn canonicalise_handles_root_and_empty_paths() {
        assert!(canonicalise_ext_path("").is_empty());
        assert!(canonicalise_ext_path("/").is_empty());
    }

    #[test]
    fn canonicalise_collapses_separators() {
        assert_eq!(canonicalise_ext_path("/foo/bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("foo/bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("//foo///bar//"), ["foo", "bar"]);
    }

    #[test]
    fn canonicalise_preserves_backslash_and_colon() {
        // Both are legal filename bytes on ext; the Windows-oriented
        // normalisation must not be applied here.
        assert_eq!(canonicalise_ext_path("/a\\b"), ["a\\b"]);
        assert_eq!(canonicalise_ext_path("/C:literal"), ["C:literal"]);
        assert_eq!(canonicalise_ext_path("/foo/a:b:c"), ["foo", "a:b:c"]);
    }

    #[test]
    fn canonicalise_resolves_dot_and_dotdot() {
        assert_eq!(canonicalise_ext_path("/./foo"), ["foo"]);
        assert_eq!(canonicalise_ext_path("/foo/./bar"), ["foo", "bar"]);
        assert_eq!(canonicalise_ext_path("/foo/../bar"), ["bar"]);
        assert_eq!(canonicalise_ext_path("/foo/bar/.."), ["foo"]);
        // `..` beyond the root is clamped rather than escaping it.
        assert_eq!(canonicalise_ext_path("/../../foo"), ["foo"]);
    }

    #[test]
    fn timestamp_zero_is_the_unix_epoch_not_unset() {
        let dt = ts_to_utc(ExtTimestamp {
            seconds: 0,
            nanoseconds: 0,
        })
        .expect("epoch is a valid ext timestamp");
        assert_eq!(dt.timestamp(), 0);
    }

    #[test]
    fn timestamp_out_of_range_maps_to_none() {
        assert!(
            ts_to_utc(ExtTimestamp {
                seconds: 0,
                nanoseconds: 2_000_000_000,
            })
            .is_none()
        );
    }

    #[test]
    fn error_mapping_preserves_semantic_variants() {
        assert!(matches!(
            map_ext_error(ExtError::NotFound, "/foo"),
            FsError::NotFound(p) if p == "/foo"
        ));
        assert!(matches!(
            map_ext_error(ExtError::NotADirectory { inode: 42 }, "/foo"),
            FsError::NotADirectory(_)
        ));
        assert!(matches!(
            map_ext_error(ExtError::IsADirectory { inode: 7 }, "/foo"),
            FsError::NotAFile(_)
        ));
        assert!(matches!(
            map_ext_error(ExtError::EncryptedInode { inode: 123 }, "/foo"),
            FsError::Filesystem(msg) if msg.contains("123") && msg.contains("encrypted")
        ));
        assert!(matches!(
            map_ext_error(ExtError::JournalExpectedButAbsent, "<open>"),
            FsError::Filesystem(msg) if msg.contains("no journal is available")
        ));
    }
}
