use super::{
    ExtError, ExtFile, ExtInode, INLINE_I_BLOCK_MAX, InlineDataState, InodeFlags, Read, Result,
    Seek, SeekFrom, Vec, read_u32_le, validate_ea_inode_size, vec,
};
use crate::io::FsReadSeek;

impl<'e> ExtInode<'e> {
    /// Whether this inline inode requires overflow bytes beyond `i_block`.
    fn needs_inline_overflow(&self) -> bool {
        if !self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            return false;
        }
        // Both files and directories use all 60 bytes of i_block
        // before overflowing to the system.data xattr.
        self.size > INLINE_I_BLOCK_MAX
    }

    /// Get the overflow payload for inline reads.
    pub(crate) fn inline_overflow(&self) -> Result<&[u8]> {
        match self.inline_state {
            InlineDataState::OverflowRange { offset, len } => match &self.ibody_xattr_data {
                Some(ibody) => Ok(&ibody[offset..offset + len]),
                None => Err(ExtError::InvalidInlineData { inode: self.number }),
            },
            InlineDataState::Invalid => Err(ExtError::InvalidInlineData { inode: self.number }),
            InlineDataState::None | InlineDataState::ShortOnly => Ok(&[]),
        }
    }

    /// Inode number (1-based).
    #[must_use]
    pub fn inode_number(&self) -> u32 {
        self.number
    }

    /// Inode generation number (from `i_generation`).
    pub(crate) fn generation(&self) -> u32 {
        self.raw.i_generation.get()
    }

    /// 48-bit external xattr block number (0 when absent).
    ///
    /// Combines `i_file_acl_lo` (low 32 bits) with the high-16-bit
    /// field stored at offset 0x76 in the extended inode buffer.
    /// Returns 0 when no xattr block is referenced.
    pub(crate) fn xattr_block_number(&self) -> u64 {
        self.xattr_block
    }

    /// Inode checksum validation state.
    #[must_use]
    pub fn checksum_state(&self) -> crate::checksum::ChecksumState {
        self.checksum_state
    }

    /// List all extended attributes on this inode.
    ///
    /// Reads from both the in-inode (ibody) xattr region and the
    /// external xattr block (if present). `EA_INODE` entries have their
    /// values resolved from the referenced inode.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or an xattr/inode validation error when any
    /// attribute source is malformed or unreadable.
    pub fn xattrs<T: Read + Seek>(&self, fs: &mut T) -> Result<Vec<crate::xattr::Xattr>> {
        let mut result = Vec::new();

        if let Some(ibody) = &self.ibody_xattr_data {
            crate::xattr::parse_ibody_entries(ibody, self.number, &mut result)?;
        }

        if self.xattr_block != 0 {
            let block_buf = self.read_xattr_block(fs)?;
            crate::xattr::parse_block_entries(&block_buf, self.number, &mut result)?;
        }

        for xattr in &mut result {
            if let Some(ea_inum) = xattr.ea_inode() {
                let value = self.read_ea_inode_value(fs, ea_inum, xattr.ea_value_size())?;
                xattr.resolve_ea_value(value);
            }
        }

        Ok(result)
    }

    /// Get a specific extended attribute by full name.
    ///
    /// Returns `Ok(Some(value))` when found, `Ok(None)` when absent.
    /// `EA_INODE` entries are resolved transparently.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or an xattr/inode validation error while reading
    /// either the inline or external attribute storage.
    pub fn xattr<T: Read + Seek>(&self, fs: &mut T, name: &str) -> Result<Option<Vec<u8>>> {
        use crate::xattr::XattrLookup;

        if let Some(ibody) = &self.ibody_xattr_data {
            match crate::xattr::find_ibody_entry(ibody, self.number, name)? {
                XattrLookup::Found(value) => return Ok(Some(value)),
                XattrLookup::EaInode { inum, value_size } => {
                    let value = self.read_ea_inode_value(fs, inum, value_size)?;
                    return Ok(Some(value));
                }
                XattrLookup::NotFound => {}
            }
        }

        if self.xattr_block != 0 {
            let block_buf = self.read_xattr_block(fs)?;
            match crate::xattr::find_block_entry(&block_buf, self.number, name)? {
                XattrLookup::Found(value) => return Ok(Some(value)),
                XattrLookup::EaInode { inum, value_size } => {
                    let value = self.read_ea_inode_value(fs, inum, value_size)?;
                    return Ok(Some(value));
                }
                XattrLookup::NotFound => {}
            }
        }

        Ok(None)
    }

    /// Get a specific extended attribute by raw `(name_index, name)`.
    ///
    /// Like [`xattr`](Self::xattr) but keys on the on-disk name index
    /// and suffix bytes directly, bypassing the string-prefix table.
    /// Needed for namespaces with no prefix mapping — e.g.
    /// `EXT4_XATTR_INDEX_VERITY` (11), whose descriptor-location xattr
    /// has an empty name.
    pub(crate) fn xattr_raw<T: Read + Seek>(
        &self,
        fs: &mut T,
        name_index: u8,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        use crate::xattr::XattrLookup;

        if let Some(ibody) = &self.ibody_xattr_data {
            match crate::xattr::find_ibody_entry_raw(ibody, self.number, name_index, name)? {
                XattrLookup::Found(value) => return Ok(Some(value)),
                XattrLookup::EaInode { inum, value_size } => {
                    let value = self.read_ea_inode_value(fs, inum, value_size)?;
                    return Ok(Some(value));
                }
                XattrLookup::NotFound => {}
            }
        }

        if self.xattr_block != 0 {
            let block_buf = self.read_xattr_block(fs)?;
            match crate::xattr::find_block_entry_raw(&block_buf, self.number, name_index, name)? {
                XattrLookup::Found(value) => return Ok(Some(value)),
                XattrLookup::EaInode { inum, value_size } => {
                    let value = self.read_ea_inode_value(fs, inum, value_size)?;
                    return Ok(Some(value));
                }
                XattrLookup::NotFound => {}
            }
        }

        Ok(None)
    }

    /// Whether this inode has the fs-verity flag (`EXT4_VERITY_FL`).
    ///
    /// Once set, the file's contents are immutable and integrity-
    /// protected by a Merkle hash tree (see [`verity_descriptor`]).
    ///
    /// [`verity_descriptor`]: Self::verity_descriptor
    #[must_use]
    pub fn is_verity(&self) -> bool {
        self.flags.contains(InodeFlags::VERITY_FL)
    }

    /// Parse this inode's `fsverity_descriptor`, if `VERITY_FL` is set.
    ///
    /// Returns `Ok(None)` for non-verity inodes. The descriptor exposes
    /// the hash algorithm, root hash, protected `data_size` and the raw
    /// PKCS#7 signature bytes; the signature chain is **not** validated.
    ///
    /// Reads the index-11 (`EXT4_XATTR_INDEX_VERITY`) descriptor-
    /// location xattr, then the 256-byte descriptor (+ signature) from
    /// the inode's data stream at `desc_pos` (kernel
    /// `ext4_get_verity_descriptor_location`).
    ///
    /// # Errors
    ///
    /// Returns an I/O, block-mapping, xattr, or
    /// [`ExtError::InvalidVerityDescriptor`] error when the descriptor cannot
    /// be located and decoded.
    #[cfg(feature = "verity")]
    pub fn verity_descriptor<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<crate::verity::VerityDescriptor>> {
        if !self.is_verity() {
            return Ok(None);
        }
        // EXT4_XATTR_INDEX_VERITY = 11, empty name.
        let location = self
            .xattr_raw(fs, 11, b"")?
            .ok_or(ExtError::InvalidVerityDescriptor {
                inode: self.number,
                reason: "VERITY_FL set but verity location xattr missing",
            })?;
        let (desc_pos, desc_size) =
            crate::verity::VerityDescriptor::parse_location(self.number, &location)?;

        let stream_len = desc_pos.checked_add(u64::from(desc_size)).ok_or(
            ExtError::InvalidVerityDescriptor {
                inode: self.number,
                reason: "verity descriptor location overflows the data stream",
            },
        )?;
        let mut stream = self.open_data_stream_unverified(stream_len)?;
        stream.seek(fs, crate::io::SeekFrom::Start(desc_pos))?;
        let mut buf = vec![0u8; desc_size as usize];
        stream.read_exact(fs, &mut buf)?;
        let descriptor = crate::verity::VerityDescriptor::parse(self.number, &buf)?;
        Ok(Some(descriptor))
    }

    /// Parsed fscrypt policy if `ENCRYPT_FL`; `Ok(None)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an I/O or xattr error, or [`ExtError::InvalidFscryptPolicy`]
    /// when an encrypted inode lacks a valid policy context.
    #[cfg(feature = "fscrypt")]
    pub fn fscrypt_policy<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<crate::fscrypt::FscryptPolicy>> {
        if !self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return Ok(None);
        }
        let bytes = self
            .xattr(fs, "encryption.c")?
            .ok_or(ExtError::InvalidFscryptPolicy {
                inode: self.number,
                reason: "ENCRYPT_FL set but encryption.c xattr missing",
            })?;
        let policy = crate::fscrypt::policy::parse_context(&bytes, self.number)?;
        Ok(Some(policy))
    }

    /// Decode `system.posix_acl_access` into typed entries, or `None` if the
    /// xattr is absent. See [`crate::posix_acl::PosixAclEntry`] for entry
    /// semantics.
    ///
    /// # Errors
    ///
    /// Returns an I/O or xattr error, or a POSIX ACL format error when the
    /// stored payload is malformed.
    pub fn posix_acl_access<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<Vec<crate::posix_acl::PosixAclEntry>>> {
        self.decode_posix_acl(fs, "system.posix_acl_access")
    }

    /// Decode `system.posix_acl_default` into typed entries, or `None` if the
    /// xattr is absent. See [`crate::posix_acl::PosixAclEntry`] for entry
    /// semantics.
    ///
    /// # Errors
    ///
    /// Returns an I/O or xattr error, or a POSIX ACL format error when the
    /// stored payload is malformed.
    pub fn posix_acl_default<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<Vec<crate::posix_acl::PosixAclEntry>>> {
        self.decode_posix_acl(fs, "system.posix_acl_default")
    }

    fn decode_posix_acl<T: Read + Seek>(
        &self,
        fs: &mut T,
        name: &str,
    ) -> Result<Option<Vec<crate::posix_acl::PosixAclEntry>>> {
        let Some(raw) = self.xattr(fs, name)? else {
            return Ok(None);
        };
        let entries = crate::posix_acl::decode(self.number, &raw)?;
        Ok(Some(entries))
    }

    /// Read the external xattr block from disk.
    fn read_xattr_block<T: Read + Seek>(&self, fs: &mut T) -> Result<Vec<u8>> {
        if self.xattr_block >= self.ext.blocks_count {
            return Err(ExtError::BlockOutOfRange {
                block: self.xattr_block,
            });
        }
        let offset = self.xattr_block * u64::from(self.ext.block_size);
        fs.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; self.ext.block_size as usize];
        fs.read_exact(&mut buf)?;

        if let Some(seed) = self.ext.checksum_seed {
            let state = crate::checksum::verify_xattr_block(seed, self.xattr_block, &buf);
            if state == crate::checksum::ChecksumState::Invalid {
                return Err(ExtError::InvalidXattrBlock {
                    inode: self.number,
                    reason: "checksum mismatch",
                });
            }
        }

        Ok(buf)
    }

    /// Read the symlink target as bytes.
    ///
    /// For unencrypted symlinks, three dispatch cases:
    /// 1. `size <= 60`: short symlink — target is in `i_block[..size]`.
    /// 2. `INLINE_DATA_FL` and `size > 60`: inline overflow symlink —
    ///    target is `i_block[0..60]` + overflow bytes from the
    ///    `system.data` xattr.
    /// 3. Otherwise: long mapped symlink — target read from data blocks
    ///    via [`ExtFile`].
    ///
    /// For fscrypt-encrypted symlinks (`ENCRYPT_FL`), reads the raw
    /// `fscrypt_symlink_data` payload via the same three-way dispatch,
    /// then decrypts via [`crate::fscrypt::symlink::decode_symlink`]
    /// when a key is registered. When the key is missing, falls back to
    /// the kernel's no-key presentation form
    /// (`base64url(fscrypt_nokey_name)`, mirroring `fscrypt_get_symlink`
    /// → `fscrypt_fname_disk_to_usr` no-key branch). Without the
    /// `fscrypt` feature, encrypted symlinks return
    /// [`ExtError::EncryptedInode`].
    ///
    /// Returns [`ExtError::InvalidInlineData`] if the overflow payload
    /// is shorter than `size - 60`.
    ///
    /// # Errors
    ///
    /// Returns an I/O or block-mapping error, an inline-data format error, or
    /// an fscrypt key/policy error while reading or decrypting the target.
    pub fn read_symlink<T: Read + Seek>(&self, fs: &mut T) -> Result<Vec<u8>> {
        #[cfg(feature = "fscrypt")]
        if self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return self.read_encrypted_symlink(fs);
        }
        #[cfg(not(feature = "fscrypt"))]
        if self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return Err(ExtError::EncryptedInode { inode: self.number });
        }

        self.read_raw_symlink_bytes(fs)
    }

    /// Read the raw on-disk symlink payload bytes via the three-way
    /// dispatch (short / inline-overflow / long-mapped).
    ///
    /// For plaintext symlinks the returned bytes are the target. For
    /// encrypted symlinks the returned bytes are the
    /// `fscrypt_symlink_data` blob (length prefix + CTS ciphertext).
    ///
    /// The long-symlink path always opens a non-encrypted `Mapped`
    /// `ExtFile` regardless of `ENCRYPT_FL`. fscrypt does NOT XTS-encrypt
    /// long-symlink data blocks: the kernel reads symlink targets via
    /// `ext4_bread` (buffer cache), which bypasses the page-cache layer
    /// where the XTS hook lives. The on-disk bytes are raw
    /// `fscrypt_symlink_data`. Routing through `EncryptedMapped` here
    /// would double-decrypt and corrupt the result.
    fn read_raw_symlink_bytes<T: Read + Seek>(&self, fs: &mut T) -> Result<Vec<u8>> {
        // EA inodes are not user-visible files and never carry a
        // symlink target. Reject the combination up-front, matching
        // the guard in `open_data_stream` so the long-symlink path
        // (which bypasses open_data_stream by design — see the
        // ExtFile::new_mapped call below) still fails closed.
        if self.flags.contains(InodeFlags::EA_INODE_FL) {
            return Err(ExtError::UnsupportedEaInode { inode: self.number });
        }
        let size = usize::try_from(self.size).map_err(|_| ExtError::InvalidInode {
            inode: self.number,
            reason: "symlink size exceeds addressable memory",
        })?;

        // Short symlink: target stored directly in i_block[..size].
        // Do NOT check EXTENTS_FL -- the 60 bytes are raw target data.
        if size <= 60 {
            return Ok(self.raw.i_block[..size].to_vec());
        }

        // Inline overflow symlink: first 60 bytes in i_block, remainder
        // from the system.data xattr payload.
        if self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            let overflow = self.inline_overflow()?;
            let overflow_needed = size - 60;
            if overflow.len() < overflow_needed {
                return Err(ExtError::InvalidInlineData { inode: self.number });
            }
            let mut target = Vec::with_capacity(size);
            target.extend_from_slice(&self.raw.i_block[..60]);
            target.extend_from_slice(&overflow[..overflow_needed]);
            return Ok(target);
        }

        // Long symlink: read target from data blocks via a plain mapped
        // ExtFile. Plaintext and encrypted symlinks both store their
        // target verbatim in data blocks (encrypted symlinks store
        // `fscrypt_symlink_data` with len+ciphertext but the bytes
        // themselves are not XTS-encrypted on disk).
        let mut file = ExtFile::new_mapped(
            self.ext,
            self.number,
            self.raw.i_generation.get(),
            self.size,
            self.raw.i_block,
            self.flags,
        );
        let mut buf = vec![0u8; size];
        file.read_exact(fs, &mut buf)?;
        Ok(buf)
    }

    #[cfg(feature = "fscrypt")]
    fn read_encrypted_symlink<T: Read + Seek>(&self, fs: &mut T) -> Result<Vec<u8>> {
        // Same fail-closed combination guard as `open_data_stream`: the
        // kernel doesn't combine ENCRYPT_FL with INLINE_DATA_FL for any
        // inode type, including symlinks, so refuse the combination
        // up-front rather than letting `read_raw_symlink_bytes` route
        // through the inline-overflow branch.
        if self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            return Err(ExtError::InvalidFscryptPolicy {
                inode: self.number,
                reason: "ENCRYPT_FL combined with INLINE_DATA_FL is not a supported \
                         on-disk state",
            });
        }
        let raw = self.read_raw_symlink_bytes(fs)?;
        let policy = self
            .fscrypt_policy(fs)?
            .ok_or(ExtError::InvalidFscryptPolicy {
                inode: self.number,
                reason: "ENCRYPT_FL set but encryption.c xattr missing",
            })?;
        match crate::fscrypt::build_filename_cipher_for_inode(self.ext, self.number, &policy) {
            Ok(cipher) => crate::fscrypt::symlink::decode_symlink(&raw, &cipher),
            // Mirrors kernel `fscrypt_get_symlink` → `fscrypt_fname_disk_to_usr`
            // (fs/crypto/hooks.c, fs/crypto/fname.c lines 295-350): when the
            // symlink is encrypted but no key is registered, return the
            // ciphertext wrapped as `base64url(fscrypt_nokey_name)` so callers
            // get the same stable ASCII string a kernel `readlink()` produces.
            // Only the missing-key case falls back; policy / IO / unsupported-mode
            // errors propagate so a real failure is not masked as a no-key string.
            Err(ExtError::MissingFscryptKey { .. }) => {
                let ct =
                    crate::fscrypt::symlink::parse_fscrypt_symlink_ciphertext(self.number, &raw)?;
                Ok(crate::fscrypt::nokey::encode_nokey_name([0, 0], ct))
            }
            Err(other) => Err(other),
        }
    }

    /// Open this inode's raw data as a seekable reader.
    ///
    /// No `IsADirectory` check — for internal use by directory
    /// iteration and symlink reading.
    pub(crate) fn open_data_stream(&self) -> Result<ExtFile<'e>> {
        if self.flags.contains(InodeFlags::EA_INODE_FL) {
            return Err(ExtError::UnsupportedEaInode { inode: self.number });
        }
        // ENCRYPT_FL must be checked BEFORE INLINE_DATA_FL: the kernel
        // fscrypt code path doesn't combine inline data with encryption,
        // so a forensic image showing both is malformed. Fail closed
        // with a structured error rather than silently bypassing the
        // fscrypt key/policy enforcement. Applies to both feature-on
        // and feature-off builds.
        if self.flags.contains(InodeFlags::ENCRYPT_FL)
            && self.flags.contains(InodeFlags::INLINE_DATA_FL)
        {
            return Err(ExtError::InvalidFscryptPolicy {
                inode: self.number,
                reason: "ENCRYPT_FL combined with INLINE_DATA_FL is not a supported \
                         on-disk state",
            });
        }
        if self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            return self.open_inline_stream();
        }
        // fs-verity-protected files route through a verifying backing
        // that checks each data block against the Merkle tree. The
        // verifier is built lazily on first read.
        #[cfg(feature = "verity")]
        if self.flags.contains(InodeFlags::VERITY_FL) {
            // ext4 permits ENCRYPT_FL + VERITY_FL together. Verifying a
            // combined-mode file means hashing decrypted blocks against
            // the Merkle tree, which is not implemented. Fail closed
            // rather than fall through to the encrypted-only path and
            // return content with no integrity check.
            if self.flags.contains(InodeFlags::ENCRYPT_FL) {
                return Err(ExtError::UnsupportedEncryptedVerity { inode: self.number });
            }
            return Ok(ExtFile::new_verity_mapped(
                self.ext,
                self.number,
                self.raw.i_generation.get(),
                self.size,
                self.raw.i_block,
                self.flags,
            ));
        }
        #[cfg(feature = "fscrypt")]
        if self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return Ok(ExtFile::new_encrypted_mapped(
                self.ext,
                self.number,
                self.raw.i_generation.get(),
                self.size,
                self.raw.i_block,
                self.flags,
            ));
        }
        #[cfg(not(feature = "fscrypt"))]
        if self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return Err(ExtError::EncryptedInode { inode: self.number });
        }
        Ok(ExtFile::new_mapped(
            self.ext,
            self.number,
            self.raw.i_generation.get(),
            self.size,
            self.raw.i_block,
            self.flags,
        ))
    }

    /// Open an EA inode's data as a seekable reader.
    ///
    /// Like [`open_data_stream()`](Self::open_data_stream) but skips
    /// the `EA_INODE_FL` guard, since EA inodes ARE data carriers.
    fn open_ea_data_stream(&self) -> Result<ExtFile<'e>> {
        if self.flags.contains(InodeFlags::ENCRYPT_FL) {
            return Err(ExtError::EncryptedInode { inode: self.number });
        }
        if self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            return self.open_inline_stream();
        }
        Ok(ExtFile::new_mapped(
            self.ext,
            self.number,
            self.raw.i_generation.get(),
            self.size,
            self.raw.i_block,
            self.flags,
        ))
    }

    /// Read the xattr value stored in a separate EA inode.
    ///
    /// `expected_size` is `e_value_size` from the xattr entry — the
    /// authoritative declared length. This is cross-checked against the
    /// EA inode's `i_size`; a mismatch indicates corruption.
    ///
    /// Verifies `EA_INODE_FL` on the target inode, reads `expected_size`
    /// bytes from its data stream, and validates the CRC32C hash
    /// stored in `i_atime` (when metadata checksums are enabled).
    ///
    /// Cycle-safe: only reads data from the EA inode, never its
    /// xattrs, so recursive EA inode references cannot loop.
    fn read_ea_inode_value<T: Read + Seek>(
        &self,
        fs: &mut T,
        ea_inum: u32,
        expected_size: u32,
    ) -> Result<Vec<u8>> {
        let ea_inode = self.ext.inode(fs, ea_inum)?;
        if !ea_inode.flags.contains(InodeFlags::EA_INODE_FL) {
            return Err(ExtError::InvalidInode {
                inode: ea_inum,
                reason: "EA inode missing EA_INODE_FL",
            });
        }

        let size = validate_ea_inode_size(ea_inum, ea_inode.size(), expected_size)?;
        let mut file = ea_inode.open_ea_data_stream()?;
        let mut buf = vec![0u8; size];
        file.read_exact(fs, &mut buf)?;

        if let Some(seed) = self.ext.checksum_seed {
            let stored_hash = ea_inode.raw.i_atime.get();
            if stored_hash != 0 {
                let computed = crate::checksum::ea_inode_hash(seed, &buf);
                if computed != stored_hash {
                    return Err(ExtError::InvalidXattrBlock {
                        inode: ea_inum,
                        reason: "EA inode value CRC32C mismatch",
                    });
                }
            }
        }

        Ok(buf)
    }

    /// Open an inline-data inode as an [`ExtFile`].
    ///
    /// Routes to `InlineShort` when the content fits in `i_block`, or
    /// `InlineOverflow` when a `system.data` xattr payload is needed.
    fn open_inline_stream(&self) -> Result<ExtFile<'e>> {
        if self.needs_inline_overflow() {
            let overflow = self.inline_overflow()?;
            if overflow.is_empty() {
                return Err(ExtError::InvalidInlineData { inode: self.number });
            }
            Ok(ExtFile::new_inline_overflow(
                self.raw.i_block,
                overflow.into(),
                self.size,
            ))
        } else {
            Ok(ExtFile::new_inline_short(self.raw.i_block, self.size))
        }
    }

    /// Open this inode's data as a seekable file reader.
    ///
    /// Returns errors for directories, encrypted inodes, and EA inodes.
    /// Inline data inodes are read transparently.
    ///
    /// # Errors
    ///
    /// Returns [`ExtError::IsADirectory`] for directories, or a feature,
    /// inline-data, fscrypt, or fs-verity setup error for unsupported or
    /// malformed inode state.
    pub fn open_file(&self) -> Result<ExtFile<'e>> {
        if self.is_directory() {
            return Err(ExtError::IsADirectory { inode: self.number });
        }
        self.open_data_stream()
    }

    /// Open this inode's data stream without any fs-verity hook.
    ///
    /// Used to read the Merkle tree and descriptor of a `VERITY_FL`
    /// inode (which live in logical blocks past `i_size`); those bytes
    /// are integrity metadata, not file data, so they bypass the
    /// per-data-block verification path. `stream_len` is the logical
    /// length the returned reader exposes — for verity metadata it must
    /// cover the bytes past `i_size`, so the caller passes the byte
    /// extent of the metadata region rather than `i_size`.
    #[cfg(feature = "verity")]
    pub(crate) fn open_data_stream_unverified(&self, stream_len: u64) -> Result<ExtFile<'e>> {
        if self.flags.contains(InodeFlags::EA_INODE_FL) {
            return Err(ExtError::UnsupportedEaInode { inode: self.number });
        }
        if self.flags.contains(InodeFlags::INLINE_DATA_FL) {
            return self.open_inline_stream();
        }
        Ok(ExtFile::new_mapped(
            self.ext,
            self.number,
            self.raw.i_generation.get(),
            stream_len,
            self.raw.i_block,
            self.flags,
        ))
    }

    /// Read the raw value bytes of this EA inode's data stream.
    ///
    /// Like [`open_data_stream()`] but skips the `EA_INODE_FL` guard.
    /// Returns up to `self.size()` bytes. Caller must already have verified
    /// `EA_INODE_FL` is set before calling this.
    pub(crate) fn read_ea_inode_value_bytes<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> crate::error::Result<alloc::vec::Vec<u8>> {
        let size = usize::try_from(self.size).map_err(|_| ExtError::InvalidInode {
            inode: self.number,
            reason: "EA inode value exceeds addressable memory",
        })?;
        let mut file = self.open_ea_data_stream()?;
        let mut buf = alloc::vec![0u8; size];
        file.read_exact(fs, &mut buf)?;
        Ok(buf)
    }

    /// If this inode has a non-zero external xattr block, read it and
    /// return the block header's `h_refcount`. Returns `None` when
    /// `xattr_block == 0`. Propagates I/O and parse errors.
    pub(crate) fn ea_inode_xattr_block_refcount<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> crate::error::Result<Option<u32>> {
        if self.xattr_block == 0 {
            return Ok(None);
        }
        let block_buf = self.read_xattr_block(fs)?;
        // h_refcount is at offset 0x04..0x08 in the xattr block header.
        if block_buf.len() < 8 {
            return Err(ExtError::InvalidXattrBlock {
                inode: self.number,
                reason: "block too short to read h_refcount",
            });
        }
        let refcount = read_u32_le(&block_buf, 4);
        Ok(Some(refcount))
    }

    /// Return the 48-bit `i_file_acl` block number stored in this inode
    /// (already resolved from `i_file_acl_lo` + osd2 high-16).
    pub(crate) fn file_acl_block(&self) -> u64 {
        self.xattr_block
    }

    /// Whether this EA inode carries any in-inode (ibody) xattr content.
    ///
    /// Returns `true` when the ibody region starts with `EXT4_XATTR_MAGIC`
    /// (0xEA020000), which is the only condition required. Does not perform
    /// full structural validation of the entries.
    pub(crate) fn ea_inode_has_ibody_xattrs(&self) -> bool {
        match &self.ibody_xattr_data {
            Some(ibody) => ibody.len() >= 4,
            None => false,
        }
    }

    /// Access the raw ibody xattr data buffer, if present.
    ///
    /// Returns `None` when no ibody xattr region was found during inode
    /// parsing. Used by EA cascade classification and test helpers to enumerate
    /// EA-inode references from the host inode's ibody region.
    pub(crate) fn ibody_xattr_data(&self) -> Option<&[u8]> {
        self.ibody_xattr_data.as_deref()
    }

    /// Raw `i_atime` field value as u32 (value-hash overload on EA inodes).
    pub(crate) fn raw_i_atime(&self) -> u32 {
        self.raw.i_atime.get()
    }

    /// `EA_INODE` refcount, kernel-overloaded onto the `i_ctime` / `l_i_version` fields.
    ///
    /// `refcount = (i_ctime as u64) << 32 | (osd1 as u64)`.
    ///
    /// On a Linux ext4 inode, `osd1` is `osd1.linux1.l_i_version` — the on-disk
    /// counterpart of the kernel-runtime `i_version_lo`. NOT to be confused with
    /// `i_generation` (offset 0x64), which is unrelated and used for inode-csum
    /// inputs.
    ///
    /// Valid only when this inode has `EA_INODE_FL` set. Returns garbage for
    /// non-EA inodes.
    pub(crate) fn ea_inode_refcount(&self) -> u64 {
        (u64::from(self.raw.i_ctime.get()) << 32) | u64::from(self.raw.osd1.get())
    }
}
