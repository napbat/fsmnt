use super::{EntryKind, Ext, ExtDirectory, ExtError, FsDirEntry, FsId, Read, Result, Seek};

/// A single directory entry yielded during traversal.
///
/// Borrows the entry name from the iterator's block buffer (`'a`) and
/// the [`Ext`] handle from the filesystem (`'e`).
pub struct ExtTraversalEntry<'e, 'a> {
    pub(super) ext: &'e Ext,
    pub(super) name: &'a [u8],
    pub(super) entry_inode: u32,
    pub(super) entry_kind: EntryKind,
}

impl<'e> ExtTraversalEntry<'e, '_> {
    /// Whether this entry is a file, directory, or other.
    #[must_use]
    pub fn kind(&self) -> EntryKind {
        self.entry_kind
    }

    /// Raw name bytes (typically UTF-8 on ext filesystems).
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        self.name
    }

    /// Stable identifier (inode number) for cycle detection.
    #[must_use]
    pub fn id(&self) -> Option<FsId> {
        if self.entry_inode == 0 {
            None
        } else {
            Some(FsId(u64::from(self.entry_inode)))
        }
    }

    /// Inode number of this entry.
    #[must_use]
    pub fn inode_number(&self) -> u32 {
        self.entry_inode
    }

    /// Open this entry as a directory for recursive traversal.
    /// Returns `Ok(None)` if this entry is not a directory.
    ///
    /// # Errors
    ///
    /// This implementation currently has no failure path; the `Result`
    /// preserves the shared filesystem-traversal trait shape.
    pub fn open_dir(&self) -> Result<Option<ExtDirectory<'e>>> {
        if self.entry_kind != EntryKind::Directory {
            return Ok(None);
        }
        Ok(Some(ExtDirectory {
            ext: self.ext,
            inode_number: self.entry_inode,
        }))
    }
}

impl<'e, R: Read + Seek> FsDirEntry<R> for ExtTraversalEntry<'e, '_> {
    type Error = ExtError;
    type Dir = ExtDirectory<'e>;

    fn kind(&self) -> EntryKind {
        self.kind()
    }

    fn name_bytes(&self) -> &[u8] {
        self.name_bytes()
    }

    fn id(&self) -> Option<FsId> {
        self.id()
    }

    fn open_dir(&self, _r: &mut R) -> Result<Option<ExtDirectory<'e>>> {
        self.open_dir()
    }
}

impl Ext {
    /// Return a directory handle for the root directory (inode 2).
    #[must_use]
    pub fn root_directory(&self) -> ExtDirectory<'_> {
        ExtDirectory {
            ext: self,
            inode_number: 2,
        }
    }

    /// Return a directory handle for the given inode number.
    #[must_use]
    pub fn directory_at(&self, inode_number: u32) -> ExtDirectory<'_> {
        ExtDirectory {
            ext: self,
            inode_number,
        }
    }
}
