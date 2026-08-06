use alloc::boxed::Box;

use fs_common::error::IoError;

use crate::block_map::{collect_block_map_blocks_into, resolve_block_map};
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::{collect_extents_into, resolve_extent};
use crate::inode::InodeFlags;
use crate::io::{FsReadSeek, Read, Seek, SeekFrom};

/// Stable stand-in for the nightly-only `OnceCell::get_or_try_init`.
///
/// Upstream used `#![feature(once_cell_try)]`; fsmnt builds on stable, so
/// the three call sites go through this helper instead. Semantics match:
/// `f` runs only when the cell is empty, and an `Err` leaves it empty.
/// `core::cell::OnceCell` is `!Sync`, so `get_or_init` cannot re-enter.
#[cfg(any(feature = "fscrypt", feature = "verity"))]
fn once_get_or_try_init<T, E>(
    cell: &core::cell::OnceCell<T>,
    f: impl FnOnce() -> core::result::Result<T, E>,
) -> core::result::Result<&T, E> {
    if let Some(value) = cell.get() {
        return Ok(value);
    }
    let value = f()?;
    Ok(cell.get_or_init(|| value))
}

/// Internal backing storage for [`ExtFile`].
///
/// Determines how file data is read: from on-disk blocks (extents or
/// indirect block map), from the 60-byte `i_block` array, or from the
/// combined `i_block` + overflow xattr payload.
enum ExtFileBacking<'e> {
    /// Standard block-backed file (extent tree or indirect map).
    Mapped {
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
    },
    /// fscrypt-encrypted block-backed file. Identical to [`Mapped`]
    /// plus a lazily-built AES-256-XTS [`ContentCipher`]. The cipher is
    /// constructed on first read so opening the file never depends on
    /// the keystore — `MissingFscryptKey` surfaces only when the caller
    /// actually tries to decrypt data.
    #[cfg(feature = "fscrypt")]
    EncryptedMapped {
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        cipher: Box<core::cell::OnceCell<crate::fscrypt::ContentCipher>>,
        /// Block-sized scratch buffer reused across reads to avoid per-call
        /// `Vec::with_capacity(block_size)` churn. Allocated lazily on
        /// first decrypted read.
        scratch: alloc::vec::Vec<u8>,
    },
    /// fs-verity-protected block-backed file. Identical to [`Mapped`]
    /// plus a lazily-built [`VerityVerifier`]. Each data block read is
    /// verified against the Merkle tree; a mismatch fails the read
    /// closed with [`ExtError::VerityHashMismatch`].
    ///
    /// [`VerityVerifier`]: crate::verity::VerityVerifier
    #[cfg(feature = "verity")]
    VerityMapped {
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        verifier: Box<core::cell::OnceCell<crate::verity::VerityVerifier>>,
        /// Block-sized scratch buffer reused across reads: the verifier
        /// needs the full (zero-padded) data block even when the caller
        /// requests a sub-block slice.
        scratch: alloc::vec::Vec<u8>,
    },
    /// Inline file that fits entirely in `i_block` (up to 60 bytes).
    /// Allocation-free: data is copied into the fixed-size array.
    InlineShort { data: [u8; 60], len: u16 },
    /// Inline file that overflows `i_block` into `system.data` xattr.
    /// First 60 bytes in `i_block`, remainder in the heap-allocated
    /// overflow payload.
    InlineOverflow {
        i_block: [u8; 60],
        overflow: Box<[u8]>,
    },
}

/// File data reader for ext2/ext3/ext4 inodes.
///
/// Implements [`FsReadSeek`] to provide sequential and random-access
/// reads of file data, routing through either the extent tree, the
/// classic indirect block map, or inline data depending on the inode.
///
/// Created via [`ExtInode::open_file()`](crate::inode::ExtInode::open_file).
pub struct ExtFile<'e> {
    backing: ExtFileBacking<'e>,
    size: u64,
    stream_pos: u64,
}

impl<'e> ExtFile<'e> {
    /// Create a mapped (block-backed) file reader.
    pub(crate) fn new_mapped(
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        size: u64,
        i_block: [u8; 60],
        i_flags: InodeFlags,
    ) -> Self {
        Self {
            backing: ExtFileBacking::Mapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
            },
            size,
            stream_pos: 0,
        }
    }

    /// Create an encrypted block-backed file reader.
    ///
    /// The AES-256-XTS cipher is built lazily on first [`read`](Self::read)
    /// call: opening the file never touches the keystore, so the public
    /// API is identical to [`new_mapped`](Self::new_mapped) and
    /// `MissingFscryptKey` only surfaces when the caller actually tries
    /// to read data.
    #[cfg(feature = "fscrypt")]
    pub(crate) fn new_encrypted_mapped(
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        size: u64,
        i_block: [u8; 60],
        i_flags: InodeFlags,
    ) -> Self {
        Self {
            backing: ExtFileBacking::EncryptedMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                cipher: Box::new(core::cell::OnceCell::new()),
                scratch: alloc::vec::Vec::new(),
            },
            size,
            stream_pos: 0,
        }
    }

    /// Create an fs-verity-protected block-backed file reader.
    ///
    /// The [`VerityVerifier`](crate::verity::VerityVerifier) is built
    /// lazily on first [`read`](Self::read): opening the file never
    /// reads the descriptor, so an absent or malformed descriptor only
    /// surfaces when the caller actually reads data.
    #[cfg(feature = "verity")]
    pub(crate) fn new_verity_mapped(
        ext: &'e Ext,
        inode_number: u32,
        generation: u32,
        size: u64,
        i_block: [u8; 60],
        i_flags: InodeFlags,
    ) -> Self {
        Self {
            backing: ExtFileBacking::VerityMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                verifier: Box::new(core::cell::OnceCell::new()),
                scratch: alloc::vec::Vec::new(),
            },
            size,
            stream_pos: 0,
        }
    }

    /// Create an inline-short file reader (data fits in `i_block`).
    pub(crate) fn new_inline_short(i_block: [u8; 60], size: u64) -> Self {
        debug_assert!(size <= 60, "InlineShort size must be <= 60");
        Self {
            backing: ExtFileBacking::InlineShort {
                data: i_block,
                len: size as u16,
            },
            size,
            stream_pos: 0,
        }
    }

    /// Create an inline-overflow file reader.
    pub(crate) fn new_inline_overflow(i_block: [u8; 60], overflow: Box<[u8]>, size: u64) -> Self {
        Self {
            backing: ExtFileBacking::InlineOverflow { i_block, overflow },
            size,
            stream_pos: 0,
        }
    }

    /// Resolve a logical block index to its physical filesystem block number.
    ///
    /// Dispatches to the extent tree (`EXTENTS_FL`) or indirect block map
    /// depending on the inode flags. Returns `Err(BlockOutOfRange)` for holes
    /// (sparse blocks map to no physical block) and for out-of-range logical
    /// indices on inline inodes.
    pub(crate) fn logical_to_physical_block<T: Read + Seek>(
        &self,
        fs: &mut T,
        logical: u32,
    ) -> crate::error::Result<u64> {
        let mapping = match &self.backing {
            ExtFileBacking::Mapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            #[cfg(feature = "fscrypt")]
            ExtFileBacking::EncryptedMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                ..
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            #[cfg(feature = "verity")]
            ExtFileBacking::VerityMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                ..
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            ExtFileBacking::InlineShort { .. } | ExtFileBacking::InlineOverflow { .. } => None,
        };
        let Some((ext, inode_number, generation, i_block, i_flags)) = mapping else {
            return Err(crate::error::ExtError::BlockOutOfRange {
                block: u64::from(logical),
            });
        };

        let extent = if i_flags.contains(InodeFlags::EXTENTS_FL) {
            crate::extent::resolve_extent(ext, fs, inode_number, generation, &i_block, logical)?
        } else {
            crate::block_map::resolve_block_map(ext, fs, &i_block, logical)?.map(|phys| {
                crate::extent::Extent {
                    logical_block: logical,
                    physical_block: phys,
                    len: 1,
                    uninitialized: false,
                }
            })
        };

        match extent {
            Some(e) if !e.uninitialized => {
                Ok(e.physical_block + u64::from(logical - e.logical_block))
            }
            _ => Err(crate::error::ExtError::BlockOutOfRange {
                block: u64::from(logical),
            }),
        }
    }

    /// Enumerate every concrete data block owned by this file and append
    /// their physical block numbers to `out`.
    ///
    /// For extent-backed files (`EXTENTS_FL`): walks the entire extent tree,
    /// including interior index blocks, and appends every allocated physical
    /// block (initialized and uninitialized).
    ///
    /// For block-map files: walks direct and indirect pointer blocks,
    /// appending both data blocks and the pointer blocks themselves.
    ///
    /// Inline files (`InlineShort` / `InlineOverflow`) own no disk blocks;
    /// `out` is left unchanged.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "called by complete_truncate indirect path; used in orphan apply tests"
        )
    )]
    pub(crate) fn owned_blocks_into<T: Read + Seek>(
        &self,
        fs: &mut T,
        out: &mut alloc::vec::Vec<u64>,
    ) -> Result<()> {
        let mapped = match &self.backing {
            ExtFileBacking::Mapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            #[cfg(feature = "fscrypt")]
            ExtFileBacking::EncryptedMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                ..
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            #[cfg(feature = "verity")]
            ExtFileBacking::VerityMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                ..
            } => Some((*ext, *inode_number, *generation, *i_block, *i_flags)),
            ExtFileBacking::InlineShort { .. } | ExtFileBacking::InlineOverflow { .. } => None,
        };
        let Some((ext, inode_number, generation, i_block, i_flags)) = mapped else {
            return Ok(());
        };
        if i_flags.contains(InodeFlags::EXTENTS_FL) {
            collect_extents_into(ext, fs, inode_number, generation, &i_block, out)
        } else {
            collect_block_map_blocks_into(ext, fs, &i_block, out)
        }
    }
}

/// Resolves and reads raw Merkle-tree / descriptor blocks for a
/// `VERITY_FL` inode.
///
/// Tree and descriptor blocks live in logical blocks of the inode past
/// `ceil(i_size / block_size)`; this adapter resolves them through the
/// extent tree or indirect block map exactly like ordinary data.
#[cfg(feature = "verity")]
struct VerityTreeReader<'a, R: Read + Seek> {
    ext: &'a Ext,
    fs: &'a mut R,
    inode_number: u32,
    generation: u32,
    i_block: [u8; 60],
    i_flags: InodeFlags,
}

#[cfg(feature = "verity")]
impl<'a, R: Read + Seek> crate::verity::TreeBlockReader for VerityTreeReader<'a, R> {
    fn read_at(&mut self, offset: u64, len: usize) -> Result<alloc::vec::Vec<u8>> {
        let block_size = u64::from(self.ext.block_size);
        let mut out = alloc::vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let cur = offset + done as u64;
            let lb = u32::try_from(cur / block_size).map_err(|_| ExtError::BlockOutOfRange {
                block: cur / block_size,
            })?;
            let in_block = (cur % block_size) as usize;
            let chunk = (block_size as usize - in_block).min(len - done);
            let physical = if self.i_flags.contains(InodeFlags::EXTENTS_FL) {
                resolve_extent(
                    self.ext,
                    self.fs,
                    self.inode_number,
                    self.generation,
                    &self.i_block,
                    lb,
                )?
            } else {
                resolve_block_map(self.ext, self.fs, &self.i_block, lb)?.map(|phys| {
                    crate::extent::Extent {
                        logical_block: lb,
                        physical_block: phys,
                        len: 1,
                        uninitialized: false,
                    }
                })
            };
            match physical {
                None => out[done..done + chunk].fill(0),
                Some(e) if e.uninitialized => out[done..done + chunk].fill(0),
                Some(e) => {
                    let blocks_into = u64::from(lb - e.logical_block);
                    let byte_offset =
                        (e.physical_block + blocks_into) * block_size + in_block as u64;
                    self.fs.seek(SeekFrom::Start(byte_offset))?;
                    self.fs.read_exact(&mut out[done..done + chunk])?;
                }
            }
            done += chunk;
        }
        Ok(out)
    }
}

/// Lazily build the [`VerityVerifier`](crate::verity::VerityVerifier)
/// for a `VERITY_FL` inode by parsing its descriptor from disk.
#[cfg(feature = "verity")]
fn build_verifier<R: Read + Seek>(
    ext: &Ext,
    fs: &mut R,
    inode_number: u32,
    i_size: u64,
) -> Result<crate::verity::VerityVerifier> {
    let inode = ext.inode(fs, inode_number)?;
    let descriptor = inode
        .verity_descriptor(fs)?
        .ok_or(ExtError::InvalidVerityDescriptor {
            inode: inode_number,
            reason: "VERITY_FL set but descriptor could not be parsed",
        })?;
    crate::verity::VerityVerifier::new(inode_number, descriptor, i_size)
}

/// Inputs for [`verity_read`]; a context struct keeps the positional
/// parameter count within the project limit.
#[cfg(feature = "verity")]
struct VerityReadCtx<'a, R: Read + Seek> {
    ext: &'a Ext,
    fs: &'a mut R,
    inode_number: u32,
    generation: u32,
    i_block: [u8; 60],
    i_flags: InodeFlags,
    verifier: &'a mut Box<core::cell::OnceCell<crate::verity::VerityVerifier>>,
    scratch: &'a mut alloc::vec::Vec<u8>,
    size: u64,
    stream_pos: u64,
    buf: &'a mut [u8],
}

/// Read and fs-verity-verify one data block of a `VERITY_FL` inode.
///
/// The verifier is built on first call. The full (zero-padded) data
/// block is read into `scratch` and checked against the Merkle tree —
/// kernel `verify_data_block` hashes whole blocks — then the requested
/// `[offset_in_block, offset_in_block + n)` slice is copied to `buf`.
/// Returns the number of bytes copied.
#[cfg(feature = "verity")]
fn verity_read<R: Read + Seek>(ctx: VerityReadCtx<'_, R>) -> Result<usize> {
    let VerityReadCtx {
        ext,
        fs,
        inode_number,
        generation,
        i_block,
        i_flags,
        verifier,
        scratch,
        size,
        stream_pos,
        buf,
    } = ctx;

    let block_size = u64::from(ext.block_size);
    let remaining_in_file = size - stream_pos;
    let logical_block = stream_pos / block_size;
    let offset_in_block = (stream_pos % block_size) as usize;
    let remaining_in_block = block_size as usize - offset_in_block;
    let n = buf
        .len()
        .min(remaining_in_file as usize)
        .min(remaining_in_block);

    let lb = u32::try_from(logical_block).map_err(|_| ExtError::BlockOutOfRange {
        block: logical_block,
    })?;

    // Build the verifier on first read; opening never touches the
    // descriptor so a malformed descriptor fails closed only here.
    once_get_or_try_init(verifier, || build_verifier(ext, fs, inode_number, size))?;
    let verifier_ref = verifier
        .get_mut()
        .ok_or(ExtError::InvalidVerityDescriptor {
            inode: inode_number,
            reason: "verity verifier unexpectedly uninitialized",
        })?;

    // Read the full data block (zero-padded past EOF) into scratch.
    let bs = block_size as usize;
    if scratch.len() != bs {
        scratch.resize(bs, 0);
    }
    let physical = if i_flags.contains(InodeFlags::EXTENTS_FL) {
        resolve_extent(ext, fs, inode_number, generation, &i_block, lb)?
    } else {
        resolve_block_map(ext, fs, &i_block, lb)?.map(|phys| crate::extent::Extent {
            logical_block: lb,
            physical_block: phys,
            len: 1,
            uninitialized: false,
        })
    };
    match physical {
        None => scratch.fill(0),
        Some(e) if e.uninitialized => scratch.fill(0),
        Some(e) => {
            let blocks_into = u64::from(lb - e.logical_block);
            let byte_offset = (e.physical_block + blocks_into) * block_size;
            fs.seek(SeekFrom::Start(byte_offset))?;
            fs.read_exact(scratch.as_mut_slice())?;
        }
    }

    // Verify the whole block against the Merkle tree before serving it.
    let mut tree_reader = VerityTreeReader {
        ext,
        fs,
        inode_number,
        generation,
        i_block,
        i_flags,
    };
    let file_offset = logical_block * block_size;
    verifier_ref.verify_data_block(&mut tree_reader, file_offset, scratch.as_slice())?;

    buf[..n].copy_from_slice(&scratch[offset_in_block..offset_in_block + n]);
    Ok(n)
}

/// Read from an inline buffer at `stream_pos` into `buf`, returning
/// the number of bytes copied. The inline content is described by
/// `i_block[0..i_block_len]` followed by `overflow[0..overflow_len]`.
fn read_inline(
    i_block: &[u8; 60],
    i_block_len: usize,
    overflow: &[u8],
    stream_pos: u64,
    size: u64,
    buf: &mut [u8],
) -> usize {
    if buf.is_empty() || stream_pos >= size {
        return 0;
    }

    let remaining = (size - stream_pos) as usize;
    let to_read = buf.len().min(remaining);
    let pos = stream_pos as usize;

    let mut written = 0;
    while written < to_read {
        let src_pos = pos + written;
        if src_pos < i_block_len {
            // Reading from i_block region
            let avail = (i_block_len - src_pos).min(to_read - written);
            buf[written..written + avail].copy_from_slice(&i_block[src_pos..src_pos + avail]);
            written += avail;
        } else {
            // Reading from overflow region
            let overflow_pos = src_pos - i_block_len;
            let avail = (overflow.len() - overflow_pos).min(to_read - written);
            buf[written..written + avail]
                .copy_from_slice(&overflow[overflow_pos..overflow_pos + avail]);
            written += avail;
        }
    }

    written
}

impl<'e, R: Read + Seek> FsReadSeek<R> for ExtFile<'e> {
    type Error = ExtError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        // Fail-closed key validation for encrypted files: any read on an
        // EncryptedMapped backing requires the key, even buf.len() == 0
        // or EOF reads. The OnceCell makes this a no-op after first use.
        #[cfg(feature = "fscrypt")]
        if let ExtFileBacking::EncryptedMapped {
            ext,
            inode_number,
            cipher,
            ..
        } = &self.backing
        {
            once_get_or_try_init(cipher, || {
                crate::fscrypt::content::build_cipher_for_inode(ext, fs, *inode_number, |fs2| {
                    let inode = ext.inode(fs2, *inode_number)?;
                    inode
                        .xattr(fs2, "encryption.c")?
                        .ok_or(ExtError::InvalidFscryptPolicy {
                            inode: *inode_number,
                            reason: "ENCRYPT_FL set but encryption.c xattr missing",
                        })
                })
            })?;
        }

        if buf.is_empty() || self.stream_pos >= self.size {
            return Ok(0);
        }

        let n = match &mut self.backing {
            ExtFileBacking::Mapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
            } => {
                let block_size = u64::from(ext.block_size);
                let remaining_in_file = self.size - self.stream_pos;
                let logical_block = self.stream_pos / block_size;
                let offset_in_block = self.stream_pos % block_size;
                let remaining_in_block = block_size - offset_in_block;

                let n = buf
                    .len()
                    .min(remaining_in_file as usize)
                    .min(remaining_in_block as usize);

                let lb = u32::try_from(logical_block).map_err(|_| ExtError::BlockOutOfRange {
                    block: logical_block,
                })?;

                let physical = if i_flags.contains(InodeFlags::EXTENTS_FL) {
                    resolve_extent(ext, fs, *inode_number, *generation, i_block, lb)?
                } else {
                    resolve_block_map(ext, fs, i_block, lb)?.map(|phys| crate::extent::Extent {
                        logical_block: lb,
                        physical_block: phys,
                        len: 1,
                        uninitialized: false,
                    })
                };

                match physical {
                    None => {
                        buf[..n].fill(0);
                    }
                    Some(ext) if ext.uninitialized => {
                        buf[..n].fill(0);
                    }
                    Some(ext) => {
                        let blocks_into = u64::from(lb - ext.logical_block);
                        let byte_offset =
                            (ext.physical_block + blocks_into) * block_size + offset_in_block;
                        fs.seek(SeekFrom::Start(byte_offset))?;
                        fs.read_exact(&mut buf[..n])?;
                    }
                }

                n
            }
            #[cfg(feature = "fscrypt")]
            ExtFileBacking::EncryptedMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                cipher,
                scratch,
            } => {
                let block_size = u64::from(ext.block_size);
                let remaining_in_file = self.size - self.stream_pos;
                let logical_block = self.stream_pos / block_size;
                let offset_in_block = self.stream_pos % block_size;
                let remaining_in_block = block_size - offset_in_block;

                let n = buf
                    .len()
                    .min(remaining_in_file as usize)
                    .min(remaining_in_block as usize);

                let lb = u32::try_from(logical_block).map_err(|_| ExtError::BlockOutOfRange {
                    block: logical_block,
                })?;

                // Build (or reuse) the AES-256-XTS cipher BEFORE we
                // resolve the block. Sparse / uninitialized regions
                // legitimately read as zeros, but a missing key or
                // unsupported policy must fail-closed regardless of
                // whether the touched block is a hole. The closure
                // re-fetches the inode + xattr from `fs`; `Ext::inode`
                // is `&self`, not `&mut`, so calling it here is safe.
                let cipher_ref = once_get_or_try_init(cipher, || {
                    crate::fscrypt::content::build_cipher_for_inode(ext, fs, *inode_number, |fs2| {
                        let inode = ext.inode(fs2, *inode_number)?;
                        inode
                            .xattr(fs2, "encryption.c")?
                            .ok_or(ExtError::InvalidFscryptPolicy {
                                inode: *inode_number,
                                reason: "ENCRYPT_FL set but encryption.c xattr missing",
                            })
                    })
                })?;

                let physical = if i_flags.contains(InodeFlags::EXTENTS_FL) {
                    resolve_extent(ext, fs, *inode_number, *generation, i_block, lb)?
                } else {
                    resolve_block_map(ext, fs, i_block, lb)?.map(|phys| crate::extent::Extent {
                        logical_block: lb,
                        physical_block: phys,
                        len: 1,
                        uninitialized: false,
                    })
                };

                match physical {
                    None => buf[..n].fill(0),
                    Some(e) if e.uninitialized => buf[..n].fill(0),
                    Some(e) => {
                        // Read and decrypt the entire physical block,
                        // then slice into the user buffer. The scratch
                        // buffer is lazily sized to block_size on first
                        // use and reused across subsequent reads.
                        let bs = block_size as usize;
                        if scratch.len() != bs {
                            scratch.resize(bs, 0);
                        }
                        let blocks_into = u64::from(lb - e.logical_block);
                        let byte_offset = (e.physical_block + blocks_into) * block_size;
                        fs.seek(SeekFrom::Start(byte_offset))?;
                        fs.read_exact(scratch.as_mut_slice())?;
                        cipher_ref.decrypt_block(scratch.as_mut_slice(), u128::from(lb))?;
                        let start = offset_in_block as usize;
                        buf[..n].copy_from_slice(&scratch[start..start + n]);
                    }
                }

                n
            }
            #[cfg(feature = "verity")]
            ExtFileBacking::VerityMapped {
                ext,
                inode_number,
                generation,
                i_block,
                i_flags,
                verifier,
                scratch,
            } => verity_read(VerityReadCtx {
                ext,
                fs,
                inode_number: *inode_number,
                generation: *generation,
                i_block: *i_block,
                i_flags: *i_flags,
                verifier,
                scratch,
                size: self.size,
                stream_pos: self.stream_pos,
                buf,
            })?,
            ExtFileBacking::InlineShort { data, len } => {
                read_inline(data, *len as usize, &[], self.stream_pos, self.size, buf)
            }
            ExtFileBacking::InlineOverflow { i_block, overflow } => {
                read_inline(i_block, 60, overflow, self.stream_pos, self.size, buf)
            }
        };

        self.stream_pos += n as u64;
        Ok(n)
    }

    fn seek(&mut self, _fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let (base, offset) = match pos {
            SeekFrom::Start(n) => {
                self.stream_pos = n;
                return Ok(n);
            }
            SeekFrom::End(n) => (self.size, n),
            SeekFrom::Current(n) => (self.stream_pos, n),
        };

        let new_pos = if offset >= 0 {
            base.checked_add(offset as u64)
        } else {
            base.checked_sub(offset.unsigned_abs())
        };

        let new_pos = new_pos.ok_or_else(|| ExtError::from(IoError::invalid_input()))?;

        self.stream_pos = new_pos;
        Ok(self.stream_pos)
    }

    fn stream_position(&self) -> u64 {
        self.stream_pos
    }

    fn len(&self) -> u64 {
        self.size
    }
}
