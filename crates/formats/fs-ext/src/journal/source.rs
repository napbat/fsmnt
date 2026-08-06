//! Locate the internal journal and read its data through the normal inode path.
//!
//! Journal file access reuses `ext.inode(fs, inum)` + `ExtInode::open_file()`.
//! The jbd2 superblock lives at block 0 of that file; other journal blocks are
//! addressed by absolute journal block number.

use super::superblock::{JournalSource, parse_journal_superblock};
use crate::block_map::resolve_block_map;
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::resolve_extent;
use crate::file::ExtFile;
use crate::io::{FsReadSeek, Read, Seek, SeekFrom};

const SB_JNL_BLOCKS_OFFSET: u64 = 0x10C;
const SB_JNL_BLOCKS_LEN: usize = 17;

#[derive(Clone, Copy, Debug)]
pub(crate) enum JournalLocator {
    Inode,
    SuperblockBackup {
        i_block: [u8; 60],
        mapping: JournalBackupMapping,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum JournalBackupMapping {
    Extents { generation: u32 },
    BlockMap,
}

#[derive(Debug)]
pub(crate) struct OpenJournalSource {
    pub(crate) source: JournalSource,
    pub(crate) locator: JournalLocator,
    pub(crate) used_superblock_backup: bool,
}

/// Compose a `JournalSource` for the internal journal.
///
/// Returns `Ok(None)` when the filesystem has no journal (ext2-style).
/// Returns `Err` when `HAS_JOURNAL` implies a journal but the inode number is
/// zero, or when the journal superblock itself fails parse, or when the
/// journal block size does not match the filesystem block size.
///
/// Note: the filesystem's `INCOMPAT_64BIT` and the journal's `_64BIT` feature
/// bits are independent (fs bit controls group-descriptor width; journal bit
/// controls tag layout). No cross-check is performed here.
pub(crate) fn open_journal_source<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
) -> Result<Option<OpenJournalSource>> {
    if !ext.has_journal() {
        if ext.needs_journal_recovery() {
            return Err(ExtError::JournalExpectedButAbsent);
        }
        return Ok(None);
    }

    let inum = ext.journal_inum();
    if inum == 0 {
        return Err(ExtError::JournalInodeZero);
    }

    match read_journal_source_from_inode(ext, fs) {
        Ok(source) => Ok(Some(OpenJournalSource {
            source,
            locator: JournalLocator::Inode,
            used_superblock_backup: false,
        })),
        Err(inode_err) => {
            let i_block = read_journal_backup_i_block(fs)?;
            let mapping = journal_backup_mapping(ext, fs, &i_block);
            match read_journal_source_from_backup(ext, fs, &i_block, mapping) {
                Ok(source) => Ok(Some(OpenJournalSource {
                    source,
                    locator: JournalLocator::SuperblockBackup { i_block, mapping },
                    used_superblock_backup: true,
                })),
                Err(_) => Err(inode_err),
            }
        }
    }
}

/// A persistent journal-file reader. Opened once at the start of the walk and
/// reused for every journal block read — the inode table is not re-parsed and
/// the `ExtFile` extent/block-map state is not recomputed per block.
pub(crate) struct JournalFile<'e> {
    backend: JournalFileBackend<'e>,
    block_size: u32,
}

enum JournalFileBackend<'e> {
    Inode(ExtFile<'e>),
    SuperblockBackup {
        ext: &'e Ext,
        i_block: [u8; 60],
        mapping: JournalBackupMapping,
    },
}

impl JournalFile<'_> {
    /// Read one journal block into `buf` by its journal block index.
    pub(crate) fn read_block<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        journal_block: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let block_size =
            usize::try_from(self.block_size).map_err(|_| ExtError::InvalidJournalSuperblock {
                reason: "journal block size exceeds addressable memory",
            })?;
        debug_assert_eq!(buf.len(), block_size);
        let journal_block =
            u32::try_from(journal_block).map_err(|_| ExtError::InvalidJournalSuperblock {
                reason: "journal block index overflow",
            })?;
        match &mut self.backend {
            JournalFileBackend::Inode(file) => {
                let offset = u64::from(journal_block)
                    .checked_mul(u64::from(self.block_size))
                    .ok_or(ExtError::InvalidJournalSuperblock {
                        reason: "journal block offset overflow",
                    })?;
                file.seek(fs, SeekFrom::Start(offset))?;
                let mut read = 0usize;
                while read < buf.len() {
                    let n = file.read(fs, &mut buf[read..])?;
                    if n == 0 {
                        return Err(ExtError::UnexpectedEof {
                            context: "journal block read",
                            offset,
                        });
                    }
                    read += n;
                }
                Ok(())
            }
            JournalFileBackend::SuperblockBackup {
                ext,
                i_block,
                mapping,
            } => {
                let journal_offset = u64::from(journal_block) * u64::from(self.block_size);
                let Some(physical) =
                    resolve_journal_backup_block(ext, fs, i_block, *mapping, journal_block)?
                else {
                    return Err(ExtError::UnexpectedEof {
                        context: "journal block read",
                        offset: journal_offset,
                    });
                };
                let byte_offset = physical * u64::from(ext.block_size());
                fs.seek(SeekFrom::Start(byte_offset))?;
                read_journal_block_exact(fs, buf, journal_offset)
            }
        }
    }

    fn read_exact_at<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let block_size =
            usize::try_from(self.block_size).map_err(|_| ExtError::InvalidJournalSuperblock {
                reason: "journal block size exceeds addressable memory",
            })?;
        let mut scratch = alloc::vec![0u8; block_size];
        let mut done = 0usize;
        while done < buf.len() {
            let absolute = offset
                .checked_add(u64::try_from(done).map_err(|_| {
                    ExtError::InvalidJournalSuperblock {
                        reason: "journal read offset exceeds u64",
                    }
                })?)
                .ok_or(ExtError::InvalidJournalSuperblock {
                    reason: "journal read offset overflow",
                })?;
            let block = absolute / u64::from(self.block_size);
            let in_block =
                usize::try_from(absolute % u64::from(self.block_size)).map_err(|_| {
                    ExtError::InvalidJournalSuperblock {
                        reason: "journal in-block offset exceeds addressable memory",
                    }
                })?;
            self.read_block(fs, block, &mut scratch)?;
            let take = core::cmp::min(block_size - in_block, buf.len() - done);
            buf[done..done + take].copy_from_slice(&scratch[in_block..in_block + take]);
            done += take;
        }
        Ok(())
    }
}

fn read_journal_source_from_inode<T: Read + Seek>(ext: &Ext, fs: &mut T) -> Result<JournalSource> {
    let inode = ext.inode(fs, ext.journal_inum())?;
    let mut file = inode.open_file()?;
    let mut sb_buf = [0u8; 1024];
    let mut read = 0usize;
    while read < sb_buf.len() {
        let n = file.read(fs, &mut sb_buf[read..])?;
        if n == 0 {
            return Err(ExtError::InvalidJournalSuperblock {
                reason: "journal file shorter than 1024 bytes",
            });
        }
        read += n;
    }
    validate_journal_source(ext, &sb_buf)
}

fn read_journal_source_from_backup<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    i_block: &[u8; 60],
    mapping: JournalBackupMapping,
) -> Result<JournalSource> {
    let mut file = JournalFile {
        backend: JournalFileBackend::SuperblockBackup {
            ext,
            i_block: *i_block,
            mapping,
        },
        block_size: ext.block_size(),
    };
    let mut sb_buf = [0u8; 1024];
    file.read_exact_at(fs, 0, &mut sb_buf)?;
    validate_journal_source(ext, &sb_buf)
}

/// Device block where the jbd2 journal area begins on an external
/// journal device.
///
/// An external journal device created by `mke2fs -O journal_dev` is not
/// a bare jbd2 log: it carries its own ext4-style superblock at byte
/// 1024, and the jbd2 journal area starts in the next full block.
/// Mirrors the kernel `ext4_get_dev_journal`:
/// `sb_block = EXT4_MIN_BLOCK_SIZE / blocksize; start = sb_block + 1`.
/// jbd2 journal block `N` (block 0 = the jbd2 superblock) is then at
/// device block `start + N`.
pub(crate) fn external_journal_base_block(block_size: u32) -> u64 {
    1024 / u64::from(block_size) + 1
}

/// Open the journal source for a filesystem whose journal lives on an
/// external device (`INCOMPAT_JOURNAL_DEV`).
///
/// The jbd2 superblock sits at device block
/// [`external_journal_base_block`] — past the journal device's own
/// ext4 superblock — not at byte 0. Validates the journal block size
/// against the filesystem and the journal UUID against `s_journal_uuid`.
pub(crate) fn open_external_journal_source<J: Read + Seek>(
    ext: &Ext,
    journal: &mut J,
) -> Result<JournalSource> {
    // The journal device uses the filesystem's block size (the kernel
    // sets `blocksize = sb->s_blocksize` before reading it); the
    // jbd2-superblock block-size field is cross-checked below.
    let block_size = ext.block_size();
    let base = external_journal_base_block(block_size);
    journal.seek(SeekFrom::Start(base * u64::from(block_size)))?;
    let mut sb_buf = [0u8; 1024];
    journal.read_exact(&mut sb_buf)?;
    let source = validate_journal_source(ext, &sb_buf)?;

    // The filesystem records the journal device's UUID in
    // `s_journal_uuid`; a mismatch means the wrong device was supplied.
    let fs_uuid = ext.journal_uuid();
    if source.uuid != fs_uuid {
        return Err(ExtError::JournalUuidMismatch {
            fs_uuid,
            journal_uuid: source.uuid,
        });
    }
    Ok(source)
}

fn validate_journal_source(ext: &Ext, sb_buf: &[u8; 1024]) -> Result<JournalSource> {
    let source = parse_journal_superblock(sb_buf)?;
    if source.block_size != ext.block_size() {
        return Err(ExtError::JournalBlockSizeMismatch {
            journal: source.block_size,
            fs: ext.block_size(),
        });
    }
    Ok(source)
}

fn journal_backup_mapping<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    i_block: &[u8; 60],
) -> JournalBackupMapping {
    if crate::extent::parse_header(i_block, ext.journal_inum()).is_ok() {
        let generation = ext
            .inode(fs, ext.journal_inum())
            .map_or(0, |inode| inode.generation());
        JournalBackupMapping::Extents { generation }
    } else {
        JournalBackupMapping::BlockMap
    }
}

fn resolve_journal_backup_block<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    i_block: &[u8; 60],
    mapping: JournalBackupMapping,
    journal_block: u32,
) -> Result<Option<u64>> {
    match mapping {
        JournalBackupMapping::Extents { generation } => Ok(resolve_extent(
            ext,
            fs,
            ext.journal_inum(),
            generation,
            i_block,
            journal_block,
        )?
        .filter(|extent| !extent.uninitialized)
        .map(|extent| extent.physical_block + u64::from(journal_block - extent.logical_block))),
        JournalBackupMapping::BlockMap => resolve_block_map(ext, fs, i_block, journal_block),
    }
}

fn read_journal_block_exact<T: Read + Seek>(
    fs: &mut T,
    buf: &mut [u8],
    journal_offset: u64,
) -> Result<()> {
    let mut read = 0usize;
    while read < buf.len() {
        let n = fs.read(&mut buf[read..])?;
        if n == 0 {
            return Err(ExtError::UnexpectedEof {
                context: "journal block read",
                offset: journal_offset,
            });
        }
        read += n;
    }
    Ok(())
}

fn read_journal_backup_i_block<T: Read + Seek>(fs: &mut T) -> Result<[u8; 60]> {
    let mut words = [0u32; SB_JNL_BLOCKS_LEN];
    fs.seek(SeekFrom::Start(
        crate::superblock::SUPERBLOCK_OFFSET + SB_JNL_BLOCKS_OFFSET,
    ))?;
    for word in &mut words {
        let mut buf = [0u8; 4];
        fs.read_exact(&mut buf)?;
        *word = u32::from_le_bytes(buf);
    }
    let mut i_block = [0u8; 60];
    for (idx, word) in words[..15].iter().enumerate() {
        i_block[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(i_block)
}

/// Open the journal inode's file once. The returned `JournalFile` borrows
/// `&'e Ext` and can be reused across the entire walk without reopening.
pub(crate) fn open_journal_file<'e, T: Read + Seek>(
    ext: &'e Ext,
    fs: &mut T,
    source: &JournalSource,
    locator: &JournalLocator,
) -> Result<JournalFile<'e>> {
    let backend = match locator {
        JournalLocator::Inode => {
            let inode = ext.inode(fs, ext.journal_inum())?;
            let file = inode.open_file()?;
            JournalFileBackend::Inode(file)
        }
        JournalLocator::SuperblockBackup { i_block, mapping } => {
            JournalFileBackend::SuperblockBackup {
                ext,
                i_block: *i_block,
                mapping: *mapping,
            }
        }
    };
    Ok(JournalFile {
        backend,
        block_size: source.block_size,
    })
}
