//! Host-directory filesystem backend.
//!
//! [`DirFilesystem`] exposes a directory on the host as a
//! [`TargetFilesystem`], letting the standalone CLI mount any folder as a
//! read-only volume.  Adapted from tracium's `StdFilesystem`, with the
//! source-remapping layer replaced by a single root directory and explicit
//! protection against paths escaping that root.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};

use crate::filesystem::{FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem};

/// Convert [`SystemTime`] to `DateTime<Utc>`.
fn system_time_to_datetime(st: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(st)
}

/// Map an [`io::Error`] to the corresponding [`FsError`], attaching `path`
/// for the not-found / permission cases.
fn io_error(path: &str, e: io::Error) -> FsError {
    match e.kind() {
        io::ErrorKind::NotFound => FsError::NotFound(path.to_string()),
        io::ErrorKind::PermissionDenied => FsError::PermissionDenied(path.to_string()),
        _ => FsError::Io(e),
    }
}

/// Build [`FsMetadata`] from std filesystem metadata.
fn metadata_from_std(meta: &std::fs::Metadata) -> FsMetadata {
    FsMetadata {
        size: meta.len(),
        is_dir: meta.is_dir(),
        created: meta.created().ok().map(system_time_to_datetime),
        modified: meta.modified().ok().map(system_time_to_datetime),
        accessed: meta.accessed().ok().map(system_time_to_datetime),
        readonly: meta.permissions().readonly(),
        hidden: false,
        system: false,
    }
}

/// A [`TargetFilesystem`] backed by a directory on the host filesystem.
///
/// All target paths are resolved relative to the root directory.  Path
/// components that would escape the root (`..`, absolute prefixes, drive
/// letters) are rejected with [`FsError::InvalidPath`].
pub struct DirFilesystem {
    root: PathBuf,
}

impl DirFilesystem {
    /// Create a filesystem rooted at `root`.
    ///
    /// The root is not validated here; operations fail with
    /// [`FsError::NotFound`] if it does not exist.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory this filesystem serves.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a target path to a host path under the root.
    ///
    /// Rejects `..` components, drive-letter prefixes, and anything else
    /// that could escape the root.
    fn resolve(&self, path: &str) -> FsResult<PathBuf> {
        let normalized = path.replace('\\', "/");
        let mut resolved = self.root.clone();
        for component in normalized.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." || component.contains(':') {
                return Err(FsError::InvalidPath(path.to_string()));
            }
            resolved.push(component);
        }
        Ok(resolved)
    }
}

impl TargetFilesystem for DirFilesystem {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let resolved = self.resolve(path)?;
        std::fs::read(&resolved).map_err(|e| io_error(path, e))
    }

    fn open(&mut self, path: &str) -> FsResult<Box<dyn Read + Send + '_>> {
        let resolved = self.resolve(path)?;
        let file = std::fs::File::open(&resolved).map_err(|e| io_error(path, e))?;
        Ok(Box::new(file))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        let resolved = self.resolve(path)?;
        resolved.try_exists().map_err(|e| io_error(path, e))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        let resolved = self.resolve(path)?;
        match std::fs::metadata(&resolved) {
            Ok(meta) => Ok(meta.is_dir()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(path, e)),
        }
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        let resolved = self.resolve(path)?;
        match std::fs::metadata(&resolved) {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(path, e)),
        }
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let resolved = self.resolve(path)?;
        let meta = std::fs::metadata(&resolved).map_err(|e| io_error(path, e))?;
        Ok(metadata_from_std(&meta))
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let resolved = self.resolve(path)?;
        let entries = std::fs::read_dir(&resolved).map_err(|e| io_error(path, e))?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(FsError::Io)?;
            let meta = entry.metadata().map_err(FsError::Io)?;
            result.push(FsEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path(),
                flags: FsEntryFlags::empty(),
                file_id: None,
                metadata: metadata_from_std(&meta),
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, DirFilesystem) {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::create_dir(dir.path().join("sub")).expect("create sub");
        std::fs::write(dir.path().join("hello.txt"), b"hello").expect("write file");
        std::fs::write(dir.path().join("sub/nested.txt"), b"nested").expect("write nested");
        let fs = DirFilesystem::new(dir.path());
        (dir, fs)
    }

    #[test]
    fn reads_file_contents() {
        let (_dir, mut fs) = fixture();
        assert_eq!(fs.read("hello.txt").expect("read"), b"hello");
        assert_eq!(fs.read("sub/nested.txt").expect("read nested"), b"nested");
    }

    #[test]
    fn accepts_leading_slash_and_backslashes() {
        let (_dir, mut fs) = fixture();
        assert_eq!(fs.read("/hello.txt").expect("read"), b"hello");
        assert_eq!(fs.read("sub\\nested.txt").expect("read"), b"nested");
    }

    #[test]
    fn rejects_parent_traversal() {
        let (_dir, mut fs) = fixture();
        let err = fs.read("../escape.txt").expect_err("must reject ..");
        assert!(matches!(err, FsError::InvalidPath(_)));
    }

    #[test]
    fn rejects_drive_letter() {
        let (_dir, mut fs) = fixture();
        let err = fs
            .read("C:/Windows/notepad.exe")
            .expect_err("must reject drive");
        assert!(matches!(err, FsError::InvalidPath(_)));
    }

    #[test]
    fn missing_file_is_not_found() {
        let (_dir, mut fs) = fixture();
        let err = fs.read("nope.txt").expect_err("must be missing");
        assert!(matches!(err, FsError::NotFound(_)));
    }

    #[test]
    fn existence_and_kind_checks() {
        let (_dir, mut fs) = fixture();
        assert!(fs.try_exists("hello.txt").expect("exists"));
        assert!(!fs.try_exists("nope.txt").expect("exists"));
        assert!(fs.try_is_dir("sub").expect("is_dir"));
        assert!(!fs.try_is_dir("hello.txt").expect("is_dir"));
        assert!(fs.try_is_file("hello.txt").expect("is_file"));
        assert!(!fs.try_is_file("sub").expect("is_file"));
    }

    #[test]
    fn metadata_reports_size_and_kind() {
        let (_dir, mut fs) = fixture();
        let meta = fs.metadata("hello.txt").expect("metadata");
        assert_eq!(meta.size, 5);
        assert!(!meta.is_dir);
        let meta = fs.metadata("sub").expect("metadata");
        assert!(meta.is_dir);
    }

    #[test]
    fn read_dir_lists_root() {
        let (_dir, mut fs) = fixture();
        let mut names: Vec<String> = fs
            .read_dir("")
            .expect("read_dir")
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, ["hello.txt", "sub"]);
    }
}
