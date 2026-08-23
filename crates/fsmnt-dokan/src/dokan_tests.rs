use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, OpenedTarget, TargetFilesystem,
    filter_entries,
};

use dokan::status::{
    STATUS_ACCESS_DENIED, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
};

use super::{DokanFs, U16CString, drive_letter_root, open_error_status, to_internal_path};

#[derive(Default)]
struct CallCounts {
    metadata: AtomicUsize,
    read_dir: AtomicUsize,
}

struct CountingFilesystem {
    calls: Arc<CallCounts>,
}

impl TargetFilesystem for CountingFilesystem {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        Err(FsError::NotAFile(path.to_string()))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        Ok(matches!(path, "file.txt" | "folder"))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        Ok(path == "folder")
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        Ok(path == "file.txt")
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        self.calls.metadata.fetch_add(1, Ordering::Relaxed);
        match path {
            "file.txt" => Ok(FsMetadata {
                size: 12,
                ..FsMetadata::default()
            }),
            "folder/visible.txt" => Ok(FsMetadata {
                size: 7,
                ..FsMetadata::default()
            }),
            "" | "folder" => Ok(FsMetadata {
                is_dir: true,
                ..FsMetadata::default()
            }),
            _ => Err(FsError::NotFound(path.to_string())),
        }
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        self.calls.read_dir.fetch_add(1, Ordering::Relaxed);
        if path != "folder" {
            return Err(FsError::NotADirectory(path.to_string()));
        }
        Ok(vec![
            entry("visible.txt", FsEntryFlags::empty(), Some(1), 7),
            entry("LongFileName.txt", FsEntryFlags::empty(), Some(2), 9),
            entry("LONGFI~1.TXT", FsEntryFlags::SHORT_NAME, Some(2), 9),
            entry("$MFT", FsEntryFlags::SYSTEM_FILE, Some(3), 1),
        ])
    }

    fn total_size(&self) -> Option<u64> {
        Some(1_024)
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(512)
    }
}

fn entry(name: &str, flags: FsEntryFlags, file_id: Option<u64>, size: u64) -> FsEntry {
    FsEntry {
        name: name.to_string(),
        path: PathBuf::from(name),
        flags,
        file_id,
        metadata: FsMetadata {
            size,
            ..FsMetadata::default()
        },
    }
}

fn filesystem() -> (DokanFs, Arc<CallCounts>) {
    let calls = Arc::new(CallCounts::default());
    let filesystem = CountingFilesystem {
        calls: Arc::clone(&calls),
    };
    let dokan = DokanFs::new(Box::new(filesystem), "NTFS".into(), "Evidence".into(), 0);
    (dokan, calls)
}

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

#[test]
fn internal_paths_are_decoded_and_normalized_in_one_pass() {
    let path = U16CString::from_str(r"\\folder\café.txt").expect("valid path");
    assert_eq!(&*to_internal_path(&path), "folder/café.txt");

    let root = U16CString::from_str(r"\").expect("valid root");
    assert!(to_internal_path(&root).is_empty());
}

#[test]
fn open_handles_reuse_their_resolved_metadata() {
    let (filesystem, calls) = filesystem();
    let opened = filesystem.open_path("file.txt".into()).expect("file opens");

    assert_eq!(opened.context.file_info().file_size, 12);
    assert_eq!(opened.context.file_info().file_size, 12);
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 1);

    let reopened = filesystem
        .open_path("file.txt".into())
        .expect("cached file opens");
    assert!(
        reopened
            .context
            .target
            .lock()
            .expect("target lock")
            .is_none()
    );
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 1);

    let root = filesystem.open_path("".into()).expect("root opens");
    assert!(root.is_dir);
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 2);
}

#[test]
fn expected_open_failures_map_to_specific_statuses() {
    for (error, expected) in [
        (
            FsError::NotFound("missing".into()),
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            FsError::NotADirectory("file/child".into()),
            STATUS_NOT_A_DIRECTORY,
        ),
        (
            FsError::NotAFile("directory".into()),
            STATUS_FILE_IS_A_DIRECTORY,
        ),
        (
            FsError::PermissionDenied("private".into()),
            STATUS_ACCESS_DENIED,
        ),
        (
            FsError::InvalidPath("../escape".into()),
            STATUS_OBJECT_NAME_INVALID,
        ),
    ] {
        assert_eq!(open_error_status("probe", error), expected);
    }
}

#[test]
fn missing_shell_probes_are_resolved_only_once() {
    let (filesystem, calls) = filesystem();
    for _ in 0..4 {
        assert!(filesystem.open_path("folder/desktop.ini".into()).is_err());
    }
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 1);
}

#[test]
fn directory_handles_load_their_listing_once() {
    let (filesystem, calls) = filesystem();
    let opened = filesystem.open_path("folder".into()).expect("folder opens");
    let mut target = opened.context.target.lock().expect("target lock");
    let Some(OpenedTarget::Directory(directory)) = &mut *target else {
        panic!("folder must open as a directory");
    };

    let (first_allocation, names, entries) = {
        let mut backend = filesystem.fs.lock().expect("filesystem lock");
        let entries = backend
            .opened_directory_entries(directory)
            .expect("first listing");
        (
            entries.as_ptr(),
            entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>(),
            entries.to_vec(),
        )
    };
    assert_eq!(
        names,
        ["visible.txt", "LongFileName.txt", "LONGFI~1.TXT", "$MFT"]
    );

    let second_allocation = {
        let mut backend = filesystem.fs.lock().expect("filesystem lock");
        backend
            .opened_directory_entries(directory)
            .expect("cached listing")
            .as_ptr()
    };
    assert_eq!(second_allocation, first_allocation);
    assert_eq!(calls.read_dir.load(Ordering::Relaxed), 1);

    filesystem.cache_directory_entries("folder", filter_entries(&entries));
    drop(target);
    let child = filesystem
        .open_path("folder/visible.txt".into())
        .expect("listed child opens from cached metadata");
    assert_eq!(child.context.file_info().file_size, 7);
    assert!(child.context.target.lock().expect("target lock").is_none());
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 1);

    let mut child_target = child.context.target.lock().expect("target lock");
    assert!(matches!(
        filesystem.ensure_target("folder/visible.txt", &mut child_target),
        Ok(OpenedTarget::File(_))
    ));
    assert_eq!(calls.metadata.load(Ordering::Relaxed), 2);
}
