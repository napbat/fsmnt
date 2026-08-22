//! Lifetime-free positioned file state for caching above the parser.

use alloc::boxed::Box;
#[cfg(any(feature = "fscrypt", feature = "verity", test))]
use alloc::vec::Vec;

use fsmnt_parser_core::error::IoError;

use crate::error::{ExtError, Result};
use crate::ext::Ext;
#[cfg(feature = "fscrypt")]
use crate::file::{EncryptedReadContext, encrypted_mapped_read};
use crate::file::{MappedReadContext, mapped_read, read_inline};
#[cfg(feature = "verity")]
use crate::file::{VerityReadCtx, verity_read};
use crate::inode::InodeFlags;
use crate::io::{Read, Seek};

/// A file-data handle detached from the inode that described it.
///
/// The handle owns the inode's compact block mapping and inline payload. With
/// fscrypt or fs-verity enabled, it also retains the lazily initialized cipher
/// or verifier and its block-sized scratch buffer across calls. This makes it
/// suitable for a bounded active-file cache without retaining an inode borrow.
pub struct ExtPositionedFile {
    backing: PositionedBacking,
    size: u64,
}

enum PositionedBacking {
    Mapped {
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
    },
    #[cfg(feature = "fscrypt")]
    EncryptedMapped {
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        cipher: Box<core::cell::OnceCell<crate::fscrypt::ContentCipher>>,
        scratch: Vec<u8>,
    },
    #[cfg(feature = "verity")]
    VerityMapped {
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        verifier: Box<core::cell::OnceCell<crate::verity::VerityVerifier>>,
        scratch: Vec<u8>,
    },
    InlineShort {
        data: [u8; 60],
        len: u16,
    },
    InlineOverflow {
        i_block: [u8; 60],
        overflow: Box<[u8]>,
    },
}

impl ExtPositionedFile {
    pub(crate) const fn mapped(
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        size: u64,
    ) -> Self {
        Self {
            backing: PositionedBacking::Mapped {
                inode_number,
                generation,
                i_block,
                i_flags,
            },
            size,
        }
    }

    #[cfg(feature = "fscrypt")]
    pub(crate) fn encrypted(
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        cipher: Box<core::cell::OnceCell<crate::fscrypt::ContentCipher>>,
        scratch: Vec<u8>,
        size: u64,
    ) -> Self {
        Self {
            backing: PositionedBacking::EncryptedMapped {
                inode_number,
                generation,
                i_block,
                i_flags,
                cipher,
                scratch,
            },
            size,
        }
    }

    #[cfg(feature = "verity")]
    pub(crate) fn verity(
        inode_number: u32,
        generation: u32,
        i_block: [u8; 60],
        i_flags: InodeFlags,
        verifier: Box<core::cell::OnceCell<crate::verity::VerityVerifier>>,
        scratch: Vec<u8>,
        size: u64,
    ) -> Self {
        Self {
            backing: PositionedBacking::VerityMapped {
                inode_number,
                generation,
                i_block,
                i_flags,
                verifier,
                scratch,
            },
            size,
        }
    }

    pub(crate) const fn inline_short(data: [u8; 60], len: u16, size: u64) -> Self {
        Self {
            backing: PositionedBacking::InlineShort { data, len },
            size,
        }
    }

    pub(crate) const fn inline_overflow(i_block: [u8; 60], overflow: Box<[u8]>, size: u64) -> Self {
        Self {
            backing: PositionedBacking::InlineOverflow { i_block, overflow },
            size,
        }
    }

    /// Returns the logical file size in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.size
    }

    /// Returns whether the file contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Reads bytes at `offset` using `ext` and its underlying source.
    ///
    /// `ext` must be the same filesystem handle from which the original
    /// [`ExtFile`](crate::ExtFile) was opened. Reads are capped at the logical
    /// end of the file and may span any number of filesystem blocks.
    ///
    /// # Errors
    ///
    /// Returns an error if block mapping, source I/O, decryption, or verity
    /// validation fails.
    pub fn read_at<T: Read + Seek>(
        &mut self,
        ext: &Ext,
        fs: &mut T,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if buffer.is_empty() || offset >= self.size {
            return Ok(0);
        }

        let available = self.size - offset;
        let limit = buffer
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let mut total = 0_usize;
        while total < limit {
            let position = offset
                .checked_add(u64::try_from(total).map_err(|_| IoError::invalid_input())?)
                .ok_or_else(|| ExtError::from(IoError::invalid_input()))?;
            let read = match &mut self.backing {
                PositionedBacking::Mapped {
                    inode_number,
                    generation,
                    i_block,
                    i_flags,
                } => mapped_read(
                    &MappedReadContext {
                        ext,
                        inode_number: *inode_number,
                        generation: *generation,
                        i_block,
                        i_flags: *i_flags,
                        size: self.size,
                        stream_pos: position,
                    },
                    fs,
                    &mut buffer[total..limit],
                )?,
                #[cfg(feature = "fscrypt")]
                PositionedBacking::EncryptedMapped {
                    inode_number,
                    generation,
                    i_block,
                    i_flags,
                    cipher,
                    scratch,
                } => encrypted_mapped_read(
                    &mut EncryptedReadContext {
                        ext,
                        inode_number: *inode_number,
                        generation: *generation,
                        i_block,
                        i_flags: *i_flags,
                        cipher,
                        scratch,
                        size: self.size,
                        stream_pos: position,
                    },
                    fs,
                    &mut buffer[total..limit],
                )?,
                #[cfg(feature = "verity")]
                PositionedBacking::VerityMapped {
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
                    stream_pos: position,
                    buf: &mut buffer[total..limit],
                })?,
                PositionedBacking::InlineShort { data, len } => read_inline(
                    data,
                    usize::from(*len),
                    &[],
                    position,
                    self.size,
                    &mut buffer[total..limit],
                ),
                PositionedBacking::InlineOverflow { i_block, overflow } => read_inline(
                    i_block,
                    60,
                    overflow,
                    position,
                    self.size,
                    &mut buffer[total..limit],
                ),
            };
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read)
                .ok_or_else(|| ExtError::from(IoError::invalid_input()))?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_testkit::Cursor;

    #[test]
    fn inline_positioned_reads_have_no_shared_cursor() {
        let mut bytes = [0_u8; 60];
        bytes[..11].copy_from_slice(b"hello world");
        let mut file = ExtPositionedFile::inline_short(bytes, 11, 11);
        let mut source = Cursor::new(Vec::<u8>::new());
        let ext = Ext::dummy_for_test();
        let mut output = [0_u8; 5];

        assert_eq!(file.read_at(ext, &mut source, 6, &mut output).unwrap(), 5);
        assert_eq!(&output, b"world");
        assert_eq!(file.read_at(ext, &mut source, 0, &mut output).unwrap(), 5);
        assert_eq!(&output, b"hello");
        assert_eq!(file.read_at(ext, &mut source, 11, &mut output).unwrap(), 0);
    }
}
