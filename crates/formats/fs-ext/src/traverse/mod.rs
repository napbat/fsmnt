//! Directory traversal for ext2/ext3/ext4 filesystems.
//!
//! Implements [`FsDirectory`], [`FsDirEntry`], and [`FsTryIterator`] to
//! enable recursive directory walking via [`fsmnt_parser_core::traverse::walk_dir`].

use alloc::vec;
use alloc::vec::Vec;

use fsmnt_parser_core::iter::{FsTryIterator, FsTryIteratorType};
use fsmnt_parser_core::traverse::{EntryKind, FsDirEntry, FsDirectory, FsId};

use crate::block_map::resolve_block_map;
use crate::directory::parse_next_entry;
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::resolve_extent;
use crate::inode::InodeFlags;
use crate::io::{Read, Seek, SeekFrom};

mod entry;
mod raw;

use raw::RawDirIterVariant;

pub use entry::ExtTraversalEntry;
pub use raw::{ExtRawDirEntry, ExtRawDirectoryIter};

/// Result of a directory name lookup.
///
/// Owned data with no lifetime ties to iterator buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtLookupEntry {
    /// Inode number of the matched entry.
    pub inode_number: u32,
    /// File type (File, Directory, or Other).
    pub kind: EntryKind,
    /// On-disk name bytes (byte-exact copy from the directory entry).
    pub name: Vec<u8>,
}

/// Directory handle for ext2/ext3/ext4 that implements [`FsDirectory`].
///
/// Created via [`Ext::root_directory()`] or [`ExtTraversalEntry::open_dir()`].
pub struct ExtDirectory<'e> {
    ext: &'e Ext,
    inode_number: u32,
}

/// Per-iterator crypto state for directory entry name decryption.
///
/// Resolved once at iterator construction time so every entry gets the
/// same decryption treatment without re-deriving the filenames key.
struct DirIterCrypto {
    /// `true` when the directory inode has `ENCRYPT_FL`. Drives
    /// [`ExtRawDirEntry::is_encrypted_name`] for raw entries.
    is_encrypted: bool,
    /// `true` when the directory has *both* `ENCRYPT_FL` and
    /// `CASEFOLD_FL` — the kernel's `ext4_hash_in_dirent(dir)`
    /// condition (`fs/ext4/ext4.h`). Such directories append an 8-byte
    /// `ext4_extended_dir_entry_2` (hash, `minor_hash`) trailer inside
    /// each non-dot entry's `rec_len`; the raw iterator extracts it so
    /// [`ExtRawDirEntry::name_nokey_encoded`] can forward it as the
    /// `fscrypt_nokey_name` dirhash.
    hash_in_dirent: bool,
    /// `Some` when the directory is encrypted AND a registered key
    /// was available. The cipher owns its zeroizing key material, so
    /// key bytes are scrubbed automatically when the cipher drops.
    ///
    /// Only present under the `fscrypt` feature; the no-fscrypt build
    /// rejects encrypted directories before constructing this struct.
    #[cfg(feature = "fscrypt")]
    filenames_cipher: Option<crate::fscrypt::FilenameCipher>,
}

impl DirIterCrypto {
    fn plaintext() -> Self {
        Self {
            is_encrypted: false,
            hash_in_dirent: false,
            #[cfg(feature = "fscrypt")]
            filenames_cipher: None,
        }
    }
}

/// Extract the `ext4_extended_dir_entry_2` (hash, `minor_hash`) trailer
/// from a directory entry in an encrypted+casefolded directory.
///
/// Mirrors the kernel `EXT4_DIRENT_HASHES` macro (`fs/ext4/ext4.h`):
/// the 8-byte trailer sits immediately after the 4-byte-rounded name,
/// i.e. at `name_start + ((name_len + 3) & !3)`, and is included
/// inside the entry's `rec_len`. Returns `InvalidDirectoryEntry` if
/// `rec_len` is too small to hold the trailer — fail-closed, without
/// touching the name bytes.
fn extract_dirhash_trailer(
    buf: &[u8],
    name_start: usize,
    name_end: usize,
    next_offset: usize,
    dir_inode: u32,
) -> Result<[u32; 2]> {
    let name_len = name_end - name_start;
    let trailer_offset = name_start + ((name_len + 3) & !3);
    if trailer_offset + 8 > next_offset || trailer_offset + 8 > buf.len() {
        return Err(ExtError::InvalidDirectoryEntry {
            inode: dir_inode,
            offset: u64::try_from(name_start).unwrap_or(u64::MAX),
        });
    }
    let hash = u32::from_le_bytes(buf[trailer_offset..trailer_offset + 4].try_into().unwrap());
    let minor_hash = u32::from_le_bytes(
        buf[trailer_offset + 4..trailer_offset + 8]
            .try_into()
            .unwrap(),
    );
    Ok([hash, minor_hash])
}

/// Decrypt the given on-disk name bytes into `name_buf` when the iterator
/// has a registered cipher. No-op for plaintext directories and for
/// encrypted directories without a key (raw iter only).
#[cfg(feature = "fscrypt")]
fn decrypt_name_into_buf(
    crypto: &DirIterCrypto,
    on_disk: &[u8],
    name_buf: &mut Vec<u8>,
) -> Result<()> {
    if let Some(cipher) = crypto.filenames_cipher.as_ref() {
        cipher.decrypt_name_into(on_disk, name_buf)?;
    }
    Ok(())
}

#[cfg(not(feature = "fscrypt"))]
fn decrypt_name_into_buf(
    _crypto: &DirIterCrypto,
    _on_disk: &[u8],
    _name_buf: &mut Vec<u8>,
) -> Result<()> {
    Ok(())
}

/// Return the appropriate name slice for the given crypto state.
///
/// When a filenames cipher is present, returns a borrow into `name_buf`
/// (filled by [`decrypt_name_into_buf`]). Otherwise returns the
/// zero-allocation borrow into the directory block buffer.
#[cfg(feature = "fscrypt")]
fn name_slice<'a>(
    crypto: &DirIterCrypto,
    block_buf: &'a [u8],
    name_start: usize,
    name_end: usize,
    name_buf: &'a [u8],
) -> &'a [u8] {
    if crypto.filenames_cipher.is_some() {
        name_buf
    } else {
        &block_buf[name_start..name_end]
    }
}

#[cfg(not(feature = "fscrypt"))]
fn name_slice<'a>(
    _crypto: &DirIterCrypto,
    block_buf: &'a [u8],
    name_start: usize,
    name_end: usize,
    _name_buf: &'a [u8],
) -> &'a [u8] {
    &block_buf[name_start..name_end]
}

impl<'e> ExtDirectory<'e> {
    /// Shared structural validation for directory access: rejects EA
    /// inodes and non-directories. Encryption is handled separately by
    /// [`Self::resolve_default_access`] / [`Self::resolve_raw_access`].
    fn validate_access_common<R: Read + Seek>(
        &self,
        r: &mut R,
    ) -> Result<crate::inode::ExtInode<'e>> {
        let inode = self.ext.inode(r, self.inode_number)?;
        if !inode.is_directory() {
            return Err(ExtError::NotADirectory {
                inode: self.inode_number,
            });
        }
        if inode.flags().contains(InodeFlags::EA_INODE_FL) {
            return Err(ExtError::UnsupportedEaInode {
                inode: self.inode_number,
            });
        }
        Ok(inode)
    }

    /// Default-API access path used by `entries()` / `lookup()`.
    ///
    /// On encrypted directories with a registered key, returns the
    /// inode plus the filenames key so the iterator can decrypt
    /// names. With no key registered, returns `MissingFscryptKey`.
    /// Plaintext directories return a no-key crypto state.
    fn resolve_default_access<R: Read + Seek>(
        &self,
        r: &mut R,
    ) -> Result<(crate::inode::ExtInode<'e>, DirIterCrypto)> {
        let inode = self.validate_access_common(r)?;
        let crypto = self.resolve_crypto_default(r, &inode)?;
        Ok((inode, crypto))
    }

    /// Raw-API access path used by `raw_entries()`.
    ///
    /// Never errors on `MissingFscryptKey`; the raw iterator simply
    /// flags emitted entries as ciphertext via
    /// [`ExtRawDirEntry::is_encrypted_name`].
    fn resolve_raw_access<R: Read + Seek>(
        &self,
        r: &mut R,
    ) -> Result<(crate::inode::ExtInode<'e>, DirIterCrypto)> {
        let inode = self.validate_access_common(r)?;
        #[cfg(feature = "fscrypt")]
        let crypto = Self::resolve_crypto_raw(&inode);
        #[cfg(not(feature = "fscrypt"))]
        let crypto = Self::resolve_crypto_raw(&inode)?;
        Ok((inode, crypto))
    }

    #[cfg(feature = "fscrypt")]
    fn resolve_crypto_default<R: Read + Seek>(
        &self,
        r: &mut R,
        inode: &crate::inode::ExtInode<'e>,
    ) -> Result<DirIterCrypto> {
        if !inode.flags().contains(InodeFlags::ENCRYPT_FL) {
            return Ok(DirIterCrypto::plaintext());
        }
        let hash_in_dirent = inode.flags().contains(InodeFlags::CASEFOLD_FL);
        let state = crate::fscrypt::directory_decryption_state(self.ext, r, inode)?;
        match state {
            crate::fscrypt::DirCryptoState::Plaintext => Ok(DirIterCrypto::plaintext()),
            crate::fscrypt::DirCryptoState::EncryptedDecryptable { cipher } => Ok(DirIterCrypto {
                is_encrypted: true,
                hash_in_dirent,
                filenames_cipher: Some(cipher),
            }),
            crate::fscrypt::DirCryptoState::EncryptedMissingKey {
                policy_kind,
                key_ref,
            } => Err(ExtError::MissingFscryptKey {
                inode: self.inode_number,
                policy_kind: alloc::format!("{policy_kind:?}"),
                key_ref,
            }),
        }
    }

    #[cfg(feature = "fscrypt")]
    fn resolve_crypto_raw(inode: &crate::inode::ExtInode<'e>) -> DirIterCrypto {
        // Raw iteration is byte-exact by contract; it never decrypts
        // and so never needs the filenames key. Recording only the
        // ENCRYPT_FL bit lets `is_encrypted_name()` work without
        // performing or storing a KDF derivation on the raw path.
        let flags = inode.flags();
        let is_encrypted = flags.contains(InodeFlags::ENCRYPT_FL);
        DirIterCrypto {
            is_encrypted,
            // `ext4_hash_in_dirent`: trailer present iff encrypted AND casefolded.
            hash_in_dirent: is_encrypted && flags.contains(InodeFlags::CASEFOLD_FL),
            filenames_cipher: None,
        }
    }

    #[cfg(not(feature = "fscrypt"))]
    fn resolve_crypto_default<R: Read + Seek>(
        &self,
        _r: &mut R,
        inode: &crate::inode::ExtInode<'e>,
    ) -> Result<DirIterCrypto> {
        if inode.flags().contains(InodeFlags::ENCRYPT_FL) {
            return Err(ExtError::EncryptedInode {
                inode: self.inode_number,
            });
        }
        Ok(DirIterCrypto::plaintext())
    }

    #[cfg(not(feature = "fscrypt"))]
    fn resolve_crypto_raw(inode: &crate::inode::ExtInode<'e>) -> Result<DirIterCrypto> {
        if inode.flags().contains(InodeFlags::ENCRYPT_FL) {
            return Err(ExtError::EncryptedInode {
                inode: inode.inode_number(),
            });
        }
        Ok(DirIterCrypto::plaintext())
    }

    /// Look up a directory entry by name.
    ///
    /// Tries htree-accelerated lookup first (if the directory has
    /// `INDEX_FL` and the filesystem has `DIR_INDEX`). Falls back to
    /// sequential scan on htree failure or missing prerequisites.
    ///
    /// For `CASEFOLD_FL` directories, comparison is case-insensitive
    /// (ASCII fast path; non-ASCII names fall through to sequential
    /// scan which also uses case-insensitive matching).
    /// Returns `ExtError::NotFound` if no entry matches.
    /// Returns `ExtError::MissingFscryptKey` for encrypted directories
    /// with no registered key.
    ///
    /// # Errors
    ///
    /// Returns an I/O, inode, directory-entry, htree, or fscrypt error while
    /// resolving and scanning the directory, including
    /// [`ExtError::NotFound`] when no entry matches.
    pub fn lookup<R: Read + Seek>(&mut self, r: &mut R, name: &[u8]) -> Result<ExtLookupEntry> {
        let (inode, crypto) = self.resolve_default_access(r)?;

        // Inline directories bypass htree entirely
        if !inode.flags().contains(InodeFlags::INLINE_DATA_FL) {
            #[cfg(feature = "fscrypt")]
            let htree_result = crate::htree::htree_lookup(
                self.ext,
                r,
                &inode,
                name,
                crypto.filenames_cipher.as_ref(),
            );
            #[cfg(not(feature = "fscrypt"))]
            let htree_result = crate::htree::htree_lookup(self.ext, r, &inode, name);
            if let Some(result) = htree_result {
                return result;
            }
        }

        // Sequential scan (only path for inline dirs, fallback for mapped)
        let casefold = inode.flags().contains(InodeFlags::CASEFOLD_FL);
        let lookup_name = crate::casefold::prepare_lookup_name(name, casefold);
        self.sequential_lookup(r, &inode, &lookup_name, crypto)
    }

    /// Sequential scan lookup (always-correct baseline).
    fn sequential_lookup<R: Read + Seek>(
        &self,
        r: &mut R,
        inode: &crate::inode::ExtInode<'e>,
        name: &crate::casefold::PreparedLookupName<'_>,
        crypto: DirIterCrypto,
    ) -> Result<ExtLookupEntry> {
        let mut iter = make_dir_iter(self.ext, inode, crypto)?;
        loop {
            let Some(entry) = iter.try_next(r)? else {
                return Err(ExtError::NotFound);
            };
            if name.matches(entry.name_bytes()) {
                return Ok(ExtLookupEntry {
                    inode_number: entry.inode_number(),
                    kind: entry.kind(),
                    name: entry.name_bytes().to_vec(),
                });
            }
        }
    }
}

impl<'e, R: Read + Seek> FsDirectory<R> for ExtDirectory<'e> {
    type Error = ExtError;
    type EntryIter = ExtDirectoryIter<'e>;

    fn entries(&mut self, r: &mut R) -> Result<ExtDirectoryIter<'e>> {
        let (inode, crypto) = self.resolve_default_access(r)?;
        make_dir_iter(self.ext, &inode, crypto)
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(u64::from(self.inode_number)))
    }
}

impl<'e> ExtDirectory<'e> {
    /// Iterate directory entries structurally, without resolving
    /// [`EntryKind`] from the child inode.
    ///
    /// Use this when you want to separate dirent parse errors (which
    /// must abort the listing) from child inode failures (which should
    /// only affect that entry's derived metadata). Particularly relevant
    /// on ext2/ext3 filesystems lacking the FILETYPE feature, where
    /// [`FsDirectory::entries`] would read the child inode eagerly.
    ///
    /// # Errors
    ///
    /// Returns an I/O, inode, inline-directory, or fscrypt error while
    /// opening the structural iterator.
    pub fn raw_entries<R: Read + Seek>(&mut self, r: &mut R) -> Result<ExtRawDirectoryIter<'e>> {
        let (inode, crypto) = self.resolve_raw_access(r)?;
        // Same fail-closed combination guard as `make_dir_iter`. The
        // raw API also rejects ENCRYPT_FL+INLINE_DATA_FL — this state
        // is not a valid kernel-fscrypt on-disk layout, and silently
        // iterating crafted images defeats the fail-closed posture.
        if inode.flags().contains(InodeFlags::ENCRYPT_FL)
            && inode.flags().contains(InodeFlags::INLINE_DATA_FL)
        {
            return Err(ExtError::InvalidFscryptPolicy {
                inode: inode.inode_number(),
                reason: "ENCRYPT_FL combined with INLINE_DATA_FL is not a supported \
                         on-disk state",
            });
        }
        if inode.flags().contains(InodeFlags::INLINE_DATA_FL) {
            let dirent_buf = build_inline_dirent_buf(&inode)?;
            Ok(ExtRawDirectoryIter {
                variant: RawDirIterVariant::Inline(InlineDirectoryIter {
                    ext: self.ext,
                    dir_inode: inode.inode_number(),
                    has_filetype: self.ext.has_filetype(),
                    dirent_buf,
                    offset: 0,
                    crypto,
                    name_buf: Vec::new(),
                }),
            })
        } else {
            Ok(ExtRawDirectoryIter {
                variant: RawDirIterVariant::Block(BlockDirectoryIter::new(
                    self.ext, &inode, crypto,
                )),
            })
        }
    }
}

/// Build the appropriate directory iterator for the given inode.
///
/// Returns an inline iterator for `INLINE_DATA_FL` directories,
/// or a block-based iterator for mapped directories.
fn make_dir_iter<'e>(
    ext: &'e Ext,
    inode: &crate::inode::ExtInode<'e>,
    crypto: DirIterCrypto,
) -> Result<ExtDirectoryIter<'e>> {
    // Same fail-closed combination guard as `open_data_stream` and
    // `read_symlink`: ENCRYPT_FL combined with INLINE_DATA_FL is not a
    // valid kernel-fscrypt on-disk state. Reject before dispatching
    // either iterator variant.
    if inode.flags().contains(InodeFlags::ENCRYPT_FL)
        && inode.flags().contains(InodeFlags::INLINE_DATA_FL)
    {
        return Err(ExtError::InvalidFscryptPolicy {
            inode: inode.inode_number(),
            reason: "ENCRYPT_FL combined with INLINE_DATA_FL is not a supported \
                     on-disk state",
        });
    }
    if inode.flags().contains(InodeFlags::INLINE_DATA_FL) {
        let dirent_buf = build_inline_dirent_buf(inode)?;
        Ok(ExtDirectoryIter {
            variant: DirIterVariant::Inline(InlineDirectoryIter {
                ext,
                dir_inode: inode.inode_number(),
                has_filetype: ext.has_filetype(),
                dirent_buf,
                offset: 0,
                crypto,
                name_buf: Vec::new(),
            }),
        })
    } else {
        Ok(ExtDirectoryIter {
            variant: DirIterVariant::Block(BlockDirectoryIter::new(ext, inode, crypto)),
        })
    }
}

/// Build a normalized dirent buffer from inline directory data.
///
/// For inline directories, the first 4 bytes of `i_block` hold the
/// parent inode number, leaving `i_block[4..60]` for directory entries.
/// If `i_size > 60`, additional bytes come from the `system.data`
/// overflow xattr.
fn build_inline_dirent_buf(inode: &crate::inode::ExtInode<'_>) -> Result<Vec<u8>> {
    let size = usize::try_from(inode.size()).map_err(|_| ExtError::InvalidInlineData {
        inode: inode.inode_number(),
    })?;
    // Dirent bytes in i_block: skip first 4 bytes (parent inode)
    let head_end = size.min(60);
    let head_len = head_end.saturating_sub(4);
    let overflow_len = size.saturating_sub(60);

    let i_block = inode.i_block();
    let mut buf = Vec::with_capacity(head_len + overflow_len);
    buf.extend_from_slice(&i_block[4..4 + head_len]);

    if overflow_len > 0 {
        let overflow = inode.inline_overflow()?;
        if overflow.len() < overflow_len {
            return Err(ExtError::InvalidInlineData {
                inode: inode.inode_number(),
            });
        }
        buf.extend_from_slice(&overflow[..overflow_len]);
    }

    Ok(buf)
}

/// Streaming iterator over ext directory entries.
///
/// Dispatches between block-based iteration (mapped directories) and
/// inline iteration (directories with `INLINE_DATA_FL`).
pub struct ExtDirectoryIter<'e> {
    variant: DirIterVariant<'e>,
}

enum DirIterVariant<'e> {
    Block(BlockDirectoryIter<'e>),
    Inline(InlineDirectoryIter<'e>),
}

/// Block-based directory iterator for mapped directories.
///
/// Reads directory data one block at a time, parsing entries on demand.
struct BlockDirectoryIter<'e> {
    ext: &'e Ext,
    dir_inode: u32,
    generation: u32,
    dir_size: u64,
    stream_pos: u64,
    has_filetype: bool,
    i_block: [u8; 60],
    i_flags: InodeFlags,
    block_buf: Vec<u8>,
    block_offset: usize,
    block_loaded: bool,
    /// fscrypt state for name decryption, captured at iter construction.
    crypto: DirIterCrypto,
    /// Per-iterator scratch buffer for decrypted names. Reused across
    /// every entry to keep allocation count down; when the directory
    /// is plaintext, this buffer is never touched.
    name_buf: Vec<u8>,
}

impl<'e> BlockDirectoryIter<'e> {
    fn new(ext: &'e Ext, inode: &crate::inode::ExtInode<'e>, crypto: DirIterCrypto) -> Self {
        Self {
            ext,
            dir_inode: inode.inode_number(),
            generation: inode.generation(),
            dir_size: inode.size(),
            stream_pos: 0,
            has_filetype: ext.has_filetype(),
            i_block: inode.i_block(),
            i_flags: inode.flags(),
            block_buf: vec![
                0u8;
                usize::try_from(ext.block_size()).expect(
                    "validated ext block sizes fit in the supported address space"
                )
            ],
            block_offset: 0,
            block_loaded: false,
            crypto,
            name_buf: Vec::new(),
        }
    }

    /// Load the directory block at the current stream position.
    fn load_block<R: Read + Seek>(&mut self, r: &mut R) -> Result<bool> {
        let block_size = u64::from(self.ext.block_size());
        if self.stream_pos >= self.dir_size {
            return Ok(false);
        }

        let logical_block = self.stream_pos / block_size;
        let lb = u32::try_from(logical_block).map_err(|_| ExtError::BlockOutOfRange {
            block: logical_block,
        })?;

        let physical = if self.i_flags.contains(InodeFlags::EXTENTS_FL) {
            resolve_extent(
                self.ext,
                r,
                self.dir_inode,
                self.generation,
                &self.i_block,
                lb,
            )?
        } else {
            resolve_block_map(self.ext, r, &self.i_block, lb)?.map(|phys| crate::extent::Extent {
                logical_block: lb,
                physical_block: phys,
                len: 1,
                uninitialized: false,
            })
        };

        match physical {
            None
            | Some(crate::extent::Extent {
                uninitialized: true,
                ..
            }) => {
                self.block_buf.fill(0);
            }
            Some(ext) => {
                let blocks_into = u64::from(lb - ext.logical_block);
                let byte_offset = (ext.physical_block + blocks_into) * block_size;
                r.seek(SeekFrom::Start(byte_offset))?;

                let remaining = self.dir_size - self.stream_pos;
                let to_read = usize::try_from(block_size.min(remaining))
                    .expect("a directory-block read is bounded by the allocated block buffer");
                r.read_exact(&mut self.block_buf[..to_read])?;
                if to_read < self.block_buf.len() {
                    self.block_buf[to_read..].fill(0);
                }

                // Validate directory block checksum. Sequential scans
                // walk both leaf blocks and htree metadata blocks;
                // dx_root/dx_node blocks legitimately return Unknown
                // here because they do not carry a dir_entry_tail.
                if let Some(seed) = self.ext.checksum_seed {
                    let state = crate::checksum::verify_dir_block(
                        seed,
                        self.dir_inode,
                        self.generation,
                        &self.block_buf,
                    );
                    if state == crate::checksum::ChecksumState::Invalid {
                        return Err(ExtError::InvalidDirectoryEntry {
                            inode: self.dir_inode,
                            offset: self.stream_pos,
                        });
                    }
                }
            }
        }

        self.block_offset = 0;
        self.block_loaded = true;
        Ok(true)
    }

    fn try_next<'a, R: Read + Seek>(
        &'a mut self,
        r: &mut R,
    ) -> Result<Option<ExtTraversalEntry<'e, 'a>>> {
        let block_size = self.block_buf.len();

        loop {
            if self.block_offset >= block_size {
                self.stream_pos +=
                    u64::try_from(block_size).expect("a validated ext block size fits in u64");
                self.block_loaded = false;
            }
            if !self.block_loaded && !self.load_block(r)? {
                return Ok(None);
            }

            let remaining_in_dir = self.dir_size - self.stream_pos;
            let usable_len =
                block_size.min(usize::try_from(remaining_in_dir).unwrap_or(usize::MAX));

            if let Some(info) = parse_next_entry(
                &self.block_buf[..usable_len],
                self.block_offset,
                self.has_filetype,
                self.dir_inode,
            )? {
                self.block_offset = info.next_offset;

                let kind =
                    resolve_kind(self.ext, r, info.file_type, info.inode, self.has_filetype)?;

                decrypt_name_into_buf(
                    &self.crypto,
                    &self.block_buf[info.name_start..info.name_end],
                    &mut self.name_buf,
                )?;

                let name = name_slice(
                    &self.crypto,
                    &self.block_buf,
                    info.name_start,
                    info.name_end,
                    &self.name_buf,
                );

                return Ok(Some(ExtTraversalEntry {
                    ext: self.ext,
                    name,
                    entry_inode: info.inode,
                    entry_kind: kind,
                }));
            }
            self.stream_pos +=
                u64::try_from(block_size).expect("a validated ext block size fits in u64");
            self.block_loaded = false;
        }
    }

    fn try_next_raw<'a, R: Read + Seek>(
        &'a mut self,
        r: &mut R,
    ) -> Result<Option<ExtRawDirEntry<'a>>> {
        let block_size = self.block_buf.len();

        loop {
            if self.block_offset >= block_size {
                self.stream_pos +=
                    u64::try_from(block_size).expect("a validated ext block size fits in u64");
                self.block_loaded = false;
            }
            if !self.block_loaded && !self.load_block(r)? {
                return Ok(None);
            }

            let remaining_in_dir = self.dir_size - self.stream_pos;
            let usable_len =
                block_size.min(usize::try_from(remaining_in_dir).unwrap_or(usize::MAX));

            if let Some(info) = parse_next_entry(
                &self.block_buf[..usable_len],
                self.block_offset,
                self.has_filetype,
                self.dir_inode,
            )? {
                self.block_offset = info.next_offset;

                // Encrypted+casefolded directories carry a per-entry
                // hash trailer inside rec_len; extract it for the
                // no-key presentation form.
                let dirhash = if self.crypto.hash_in_dirent {
                    extract_dirhash_trailer(
                        &self.block_buf[..usable_len],
                        info.name_start,
                        info.name_end,
                        info.next_offset,
                        self.dir_inode,
                    )?
                } else {
                    [0, 0]
                };

                // Raw iteration is byte-exact by contract — never
                // decrypt. Callers use `is_encrypted_name()` to know
                // whether bytes are ciphertext.
                return Ok(Some(ExtRawDirEntry {
                    name: &self.block_buf[info.name_start..info.name_end],
                    inode_number: info.inode,
                    file_type: info.file_type,
                    encrypted: self.crypto.is_encrypted,
                    dirhash,
                }));
            }
            self.stream_pos +=
                u64::try_from(block_size).expect("a validated ext block size fits in u64");
            self.block_loaded = false;
        }
    }
}

/// Inline directory iterator for directories with `INLINE_DATA_FL`.
///
/// Walks a pre-built dirent buffer assembled from `i_block[4..]` and
/// optional overflow payload.
struct InlineDirectoryIter<'e> {
    ext: &'e Ext,
    dir_inode: u32,
    has_filetype: bool,
    dirent_buf: Vec<u8>,
    offset: usize,
    /// fscrypt state for name decryption, captured at iter construction.
    crypto: DirIterCrypto,
    /// Per-iterator scratch buffer for decrypted names. See
    /// [`BlockDirectoryIter::name_buf`].
    name_buf: Vec<u8>,
}

impl<'e> InlineDirectoryIter<'e> {
    fn try_next<'a, R: Read + Seek>(
        &'a mut self,
        r: &mut R,
    ) -> Result<Option<ExtTraversalEntry<'e, 'a>>> {
        let entry = parse_next_entry(
            &self.dirent_buf,
            self.offset,
            self.has_filetype,
            self.dir_inode,
        )?;

        let Some(info) = entry else {
            return Ok(None);
        };

        self.offset = info.next_offset;

        let kind = resolve_kind(self.ext, r, info.file_type, info.inode, self.has_filetype)?;

        decrypt_name_into_buf(
            &self.crypto,
            &self.dirent_buf[info.name_start..info.name_end],
            &mut self.name_buf,
        )?;

        let name = name_slice(
            &self.crypto,
            &self.dirent_buf,
            info.name_start,
            info.name_end,
            &self.name_buf,
        );

        Ok(Some(ExtTraversalEntry {
            ext: self.ext,
            name,
            entry_inode: info.inode,
            entry_kind: kind,
        }))
    }

    fn try_next_raw<'a, R: Read + Seek>(
        &'a mut self,
        _r: &mut R,
    ) -> Result<Option<ExtRawDirEntry<'a>>> {
        let entry = parse_next_entry(
            &self.dirent_buf,
            self.offset,
            self.has_filetype,
            self.dir_inode,
        )?;

        let Some(info) = entry else {
            return Ok(None);
        };

        self.offset = info.next_offset;

        let dirhash = if self.crypto.hash_in_dirent {
            extract_dirhash_trailer(
                &self.dirent_buf,
                info.name_start,
                info.name_end,
                info.next_offset,
                self.dir_inode,
            )?
        } else {
            [0, 0]
        };

        // Raw iteration is byte-exact by contract — never decrypt.
        let name = &self.dirent_buf[info.name_start..info.name_end];

        Ok(Some(ExtRawDirEntry {
            name,
            inode_number: info.inode,
            file_type: info.file_type,
            encrypted: self.crypto.is_encrypted,
            dirhash,
        }))
    }
}

impl<'e> FsTryIteratorType for ExtDirectoryIter<'e> {
    type Error = ExtError;
    type Item<'a> = ExtTraversalEntry<'e, 'a>;
}

impl<'e, R: Read + Seek> FsTryIterator<R> for ExtDirectoryIter<'e> {
    fn try_next<'a>(&'a mut self, r: &mut R) -> Result<Option<ExtTraversalEntry<'e, 'a>>> {
        match &mut self.variant {
            DirIterVariant::Block(block) => block.try_next(r),
            DirIterVariant::Inline(inline) => inline.try_next(r),
        }
    }
}

/// Resolve the [`EntryKind`] from a file type byte or by reading the
/// child inode's mode.
pub(crate) fn resolve_kind<R: Read + Seek>(
    ext: &Ext,
    r: &mut R,
    file_type: u8,
    child_inode: u32,
    has_filetype: bool,
) -> Result<EntryKind> {
    if has_filetype {
        // fs/ext4/ext4.h:2405-2412 — EXT4_FT_* constants.
        return Ok(match file_type {
            1 /* EXT4_FT_REG_FILE */ => EntryKind::File,
            2 /* EXT4_FT_DIR */      => EntryKind::Directory,
            3 /* EXT4_FT_CHRDEV */   => EntryKind::CharDevice,
            4 /* EXT4_FT_BLKDEV */   => EntryKind::BlockDevice,
            5 /* EXT4_FT_FIFO */     => EntryKind::Fifo,
            6 /* EXT4_FT_SOCK */     => EntryKind::Socket,
            7 /* EXT4_FT_SYMLINK */  => EntryKind::Symlink,
            _ /* EXT4_FT_UNKNOWN, future */ => EntryKind::Other,
        });
    }

    // No FILETYPE feature: read the child inode and map by POSIX mode.
    let inode = ext.inode(r, child_inode)?;
    Ok(match inode.kind() {
        crate::inode::ExtFileKind::RegularFile => EntryKind::File,
        crate::inode::ExtFileKind::Directory => EntryKind::Directory,
        crate::inode::ExtFileKind::Symlink => EntryKind::Symlink,
        crate::inode::ExtFileKind::Fifo => EntryKind::Fifo,
        crate::inode::ExtFileKind::CharacterDevice => EntryKind::CharDevice,
        crate::inode::ExtFileKind::BlockDevice => EntryKind::BlockDevice,
        crate::inode::ExtFileKind::Socket => EntryKind::Socket,
        crate::inode::ExtFileKind::Unknown => EntryKind::Other,
    })
}

#[cfg(test)]
#[path = "../traverse_tests/mod.rs"]
mod tests;
