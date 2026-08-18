use super::{
    BlockDirectoryIter, ExtError, FsTryIterator, FsTryIteratorType, InlineDirectoryIter, Read,
    Result, Seek,
};

/// Byte-exact directory entry from [`ExtDirectory::raw_entries`].
///
/// Contrast with [`ExtTraversalEntry`] (from `entries()`), which
/// pre-resolves [`EntryKind`] by reading the child inode when the
/// filesystem lacks the FILETYPE feature. `ExtRawDirEntry` yields
/// only the structural dirent fields, so callers can separate
/// "dirent parse errors" from "child inode read errors" and degrade
/// the latter without aborting the listing.
pub struct ExtRawDirEntry<'a> {
    pub(super) name: &'a [u8],
    pub(super) inode_number: u32,
    pub(super) file_type: u8,
    pub(super) encrypted: bool,
    /// `(hash, minor_hash)` from the entry's `ext4_extended_dir_entry_2`
    /// trailer. Non-zero only for encrypted+casefolded directories;
    /// `[0, 0]` otherwise (matching the kernel's non-casefolded dirhash).
    pub(super) dirhash: [u32; 2],
}

impl<'a> ExtRawDirEntry<'a> {
    /// Byte-exact entry name from the directory block.
    ///
    /// For encrypted directories with no registered key this is the
    /// raw on-disk ciphertext; check [`Self::is_encrypted_name`].
    #[must_use]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Inode number the entry points to.
    #[must_use]
    pub fn inode_number(&self) -> u32 {
        self.inode_number
    }

    /// Raw `file_type` byte from the on-disk dirent.
    ///
    /// On filesystems with the FILETYPE feature this is an
    /// `EXT4_FT_*` value (1 = regular file, 2 = directory, 7 =
    /// symlink, etc.). On filesystems without FILETYPE this is
    /// always 0 — the caller must read the child inode to
    /// determine kind.
    #[must_use]
    pub fn file_type(&self) -> u8 {
        self.file_type
    }

    /// Whether the directory holding this entry has fscrypt enabled.
    ///
    /// When `true`, [`Self::name_bytes`] returns the on-disk ciphertext
    /// bytes verbatim — the raw iterator never decrypts entry names by
    /// contract, regardless of whether a fscrypt key is registered.
    /// Callers that want plaintext names should use the default
    /// [`ExtDirectory::entries`] / [`ExtDirectory::lookup`] APIs which
    /// transparently decrypt.
    #[must_use]
    pub fn is_encrypted_name(&self) -> bool {
        self.encrypted
    }

    /// Entry name in the kernel's no-key presentation form.
    ///
    /// Mirrors `fscrypt_fname_disk_to_usr`'s no-key branch
    /// (`fs/crypto/fname.c` lines 295-350): for [`Self::is_encrypted_name`]
    /// entries the on-disk ciphertext is wrapped in `fscrypt_nokey_name`
    /// and base64url-encoded, producing the same stable ASCII string a
    /// kernel `readdir()` would return when no key is registered.
    /// Plaintext entries — and the `.` / `..` self/parent links, which
    /// the kernel short-circuits via `fscrypt_is_dot_dotdot` even on
    /// encrypted directories — pass through as a byte copy.
    ///
    /// The `dirhash` is `[0, 0]` for non-casefolded encrypted
    /// directories — matching `fs/ext4/dir.c::ext4_readdir`, which only
    /// reads a per-entry hash when `IS_CASEFOLDED(dir)`. For encrypted
    /// *and* casefolded directories it is the on-disk
    /// `ext4_extended_dir_entry_2` (hash, `minor_hash`) trailer the raw
    /// iterator extracted, so the no-key string byte-matches the
    /// kernel's `readdir()` output for those directories too.
    #[cfg(feature = "fscrypt")]
    #[must_use]
    pub fn name_nokey_encoded(&self) -> alloc::vec::Vec<u8> {
        // Kernel `fscrypt_fname_disk_to_usr` short-circuits dot entries
        // before the no-key branch: `if (fscrypt_is_dot_dotdot(&qname)) {
        // ...; return 0; }`. Today our `parse_next_entry` skips dot
        // entries before they reach `ExtRawDirEntry`, so this branch is
        // defensive against a future iterator that surfaces them — the
        // public method must mirror the kernel invariant regardless.
        if self.encrypted && self.name != b"." && self.name != b".." {
            crate::fscrypt::encode_nokey_name(self.dirhash, self.name)
        } else {
            self.name.to_vec()
        }
    }

    /// Entry name in the kernel's no-key presentation form.
    ///
    /// Without the `fscrypt` feature, encrypted directories are rejected
    /// upstream so this method only ever sees plaintext entries. Returns
    /// a byte copy of [`Self::name_bytes`].
    #[cfg(not(feature = "fscrypt"))]
    pub fn name_nokey_encoded(&self) -> alloc::vec::Vec<u8> {
        self.name.to_vec()
    }
}

/// Streaming iterator over byte-exact directory entries.
///
/// See [`ExtDirectory::raw_entries`].
pub struct ExtRawDirectoryIter<'e> {
    pub(super) variant: RawDirIterVariant<'e>,
}

pub(super) enum RawDirIterVariant<'e> {
    Block(BlockDirectoryIter<'e>),
    Inline(InlineDirectoryIter<'e>),
}

impl FsTryIteratorType for ExtRawDirectoryIter<'_> {
    type Error = ExtError;
    type Item<'a> = ExtRawDirEntry<'a>;
}

impl<R: Read + Seek> FsTryIterator<R> for ExtRawDirectoryIter<'_> {
    fn try_next<'a>(&'a mut self, r: &mut R) -> Result<Option<ExtRawDirEntry<'a>>> {
        match &mut self.variant {
            RawDirIterVariant::Block(block) => block.try_next_raw(r),
            RawDirIterVariant::Inline(inline) => inline.try_next_raw(r),
        }
    }
}
