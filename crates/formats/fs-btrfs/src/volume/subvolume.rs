//! Subvolume root discovery and explicit selection.

use fsmnt_parser_core::io::{Read, Seek};

use super::Btrfs;
use crate::item::{BtrfsFileType, FIRST_FREE_OBJECT_ID, FS_TREE_OBJECT_ID};
use crate::{BtrfsEntry, BtrfsError, Result};

impl<R: Read + Seek> Btrfs<R> {
    /// Tree identifier selected by the filesystem's default-subvolume entry.
    ///
    /// This is the top-level filesystem tree (ID 5) when no explicit default
    /// subvolume is recorded.
    ///
    /// # Errors
    ///
    /// Returns an error if volume initialization or default-root validation
    /// fails.
    pub fn default_subvolume_id(&mut self) -> Result<u64> {
        self.initialize()?;
        Ok(self.default_tree_id)
    }

    /// Return the root of Btrfs's top-level filesystem tree (tree ID 5).
    ///
    /// # Errors
    ///
    /// Returns an error if the top-level tree or its root inode cannot be read
    /// and validated.
    pub fn top_level_root(&mut self) -> Result<BtrfsEntry> {
        self.subvolume_root(FS_TREE_OBJECT_ID)
    }

    /// Return the root inode of a subvolume or snapshot tree.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::TreeRootNotFound`] when `tree_id` does not name a
    /// filesystem tree, or another parsing/I/O error when its root cannot be
    /// validated.
    pub fn subvolume_root(&mut self, tree_id: u64) -> Result<BtrfsEntry> {
        self.initialize()?;
        if !crate::item::valid_filesystem_tree_id(tree_id) {
            return Err(BtrfsError::TreeRootNotFound { tree_id });
        }
        let root = self.lookup_tree_root(tree_id)?;
        let inode = self.inode_from_root(root, FIRST_FREE_OBJECT_ID)?;
        if !inode.file_type().is_directory() {
            return Err(BtrfsError::NotADirectory);
        }
        Ok(BtrfsEntry {
            tree_id,
            object_id: FIRST_FREE_OBJECT_ID,
            file_type: BtrfsFileType::Directory,
        })
    }

    /// Resolve a subvolume or snapshot path from the top-level tree.
    ///
    /// Components are byte-exact Btrfs names. The final component must resolve
    /// to a subvolume root rather than an ordinary directory.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotASubvolume`] when the path exists but does not
    /// end at a subvolume root, or the first lookup, tree, or I/O error.
    pub fn subvolume_at_path<'component>(
        &mut self,
        components: impl IntoIterator<Item = &'component [u8]>,
    ) -> Result<BtrfsEntry> {
        let top_level = self.top_level_root()?;
        let entry = self.resolve_path_from(top_level, components)?;
        if entry.object_id != FIRST_FREE_OBJECT_ID {
            return Err(BtrfsError::NotASubvolume);
        }
        self.subvolume_root(entry.tree_id)
    }

    /// Resolve path components from an explicitly supplied directory root.
    ///
    /// # Errors
    ///
    /// Returns the first directory lookup, tree, or I/O error encountered.
    pub fn resolve_path_from<'component>(
        &mut self,
        root: BtrfsEntry,
        components: impl IntoIterator<Item = &'component [u8]>,
    ) -> Result<BtrfsEntry> {
        let mut current = root;
        for component in components {
            current = self.lookup(current, component)?;
        }
        Ok(current)
    }
}
