//! Directory listing for the ext adapter.
//!
//! Split out of [`super`] so each file stays well under the crate's
//! 1000-line ceiling; [`list`] is the body of
//! [`ExtFilesystem::read_dir`](super::ExtFilesystem::read_dir).

use std::path::PathBuf;

use fs_common::iter::FsTryIterator;
use fs_ext::Ext;
use fs_ext::io::{Read, Seek};
use fsmnt_core::{FsEntry, FsEntryFlags, FsMetadata, FsResult};

use super::{Reader, map_ext_error, ts_to_utc};

/// Directory-entry `file_type` byte for a directory (`EXT4_FT_DIR`).
///
/// On filesystems without the `FILETYPE` feature this byte is always 0 and
/// the kind must come from the child inode instead.
const EXT4_FT_DIR: u8 = 2;
/// Directory-entry `file_type` byte for a symlink (`EXT4_FT_SYMLINK`).
const EXT4_FT_SYMLINK: u8 = 7;

/// Build the metadata and flags for one child inode, degrading gracefully.
///
/// A failed inode read falls back to the raw dirent `file_type` byte, so a
/// single corrupt child only sparsifies its own entry instead of aborting
/// the whole listing. Where that byte is absent (no `FILETYPE` feature) the
/// entry is reported as an unknown kind: neither directory nor symlink.
fn describe<R: Read + Seek>(
    ext: &Ext,
    reader: &mut Reader<'_, R>,
    inum: u32,
    file_type: u8,
) -> (FsMetadata, FsEntryFlags) {
    let Ok(inode) = ext.inode(reader, inum) else {
        let mut flags = FsEntryFlags::empty();
        if file_type == EXT4_FT_SYMLINK {
            flags |= FsEntryFlags::REPARSE_POINT;
        }
        let metadata = FsMetadata {
            is_dir: file_type == EXT4_FT_DIR,
            ..FsMetadata::default()
        };
        return (metadata, flags);
    };

    let is_dir = inode.is_directory();
    let mut flags = FsEntryFlags::empty();
    if inode.is_symlink() {
        flags |= FsEntryFlags::REPARSE_POINT;
    }

    let metadata = FsMetadata {
        size: if is_dir { 0 } else { inode.size() },
        is_dir,
        created: inode.crtime().and_then(ts_to_utc),
        modified: ts_to_utc(inode.mtime()),
        accessed: ts_to_utc(inode.atime()),
        readonly: false,
        hidden: false,
        system: false,
    };
    (metadata, flags)
}

/// List the directory at `inum`, reporting entry paths under `path`.
///
/// Runs in two passes. The first is purely structural and uses
/// `raw_entries`, so iterator errors can only come from dirent parsing and
/// never from a per-child inode read. The second fills in content,
/// best-effort per entry.
///
/// # Errors
///
/// Returns an error if `inum` is not a directory or its dirent blocks
/// cannot be parsed.
pub(super) fn list<R: Read + Seek>(
    ext: &Ext,
    reader: &mut Reader<'_, R>,
    inum: u32,
    path: &str,
) -> FsResult<Vec<FsEntry>> {
    // Entries inherit the caller's path verbatim, matching the NTFS
    // adapter: read_dir("C:\\Windows") reports "C:\\Windows\\foo".
    let parent_path = PathBuf::from(path);

    let mut raw: Vec<(Vec<u8>, u32, u8)> = Vec::new();
    {
        let mut dir = ext.directory_at(inum);
        let mut iter = dir
            .raw_entries(reader)
            .map_err(|e| map_ext_error(e, path))?;
        while let Some(entry) = iter.try_next(reader).map_err(|e| map_ext_error(e, path))? {
            let name_bytes = entry.name_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            raw.push((name_bytes.to_vec(), entry.inode_number(), entry.file_type()));
        }
    }

    let mut entries = Vec::with_capacity(raw.len());
    for (name_bytes, entry_inum, file_type) in raw {
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let (metadata, flags) = describe(ext, reader, entry_inum, file_type);

        entries.push(FsEntry {
            path: parent_path.join(&name),
            name,
            flags,
            file_id: Some(u64::from(entry_inum)),
            metadata,
        });
    }
    Ok(entries)
}
