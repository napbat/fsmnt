use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use zerocopy::byteorder::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::file::ExtFile;
use crate::io::{Read, Seek, SeekFrom};
use crate::time::{ExtTimestamp, base_timestamp, decode_extended_timestamp};

mod data;

/// On-disk inode base structure (exactly 128 bytes).
///
/// Present in every inode regardless of `s_inode_size`. Extended fields
/// (timestamps, checksums, project ID) live beyond byte 128 and are
/// parsed separately in future phases.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawInode {
    /// 0x00: File type and permission bits.
    pub i_mode: U16<LE>,
    /// 0x02: Lower 16 bits of the owner UID.
    pub i_uid: U16<LE>,
    /// 0x04: Lower 32 bits of the file size in bytes.
    pub i_size_lo: U32<LE>,
    /// 0x08: Last access time (signed 32-bit seconds since epoch).
    pub i_atime: U32<LE>,
    /// 0x0C: Last inode change time (signed 32-bit seconds since epoch).
    pub i_ctime: U32<LE>,
    /// 0x10: Last data modification time (signed 32-bit seconds since epoch).
    pub i_mtime: U32<LE>,
    /// 0x14: Deletion time (signed 32-bit seconds since epoch).
    pub i_dtime: U32<LE>,
    /// 0x18: Lower 16 bits of the owner GID.
    pub i_gid: U16<LE>,
    /// 0x1A: Hard link count.
    pub i_links_count: U16<LE>,
    /// 0x1C: Lower 32 bits of the block count (512-byte sectors by default).
    pub i_blocks_lo: U32<LE>,
    /// 0x20: Inode flags (extents, encryption, inline data, etc).
    pub i_flags: U32<LE>,
    /// 0x24: OS-dependent value 1.
    pub osd1: U32<LE>,
    /// 0x28: Block mapping array (15 x 4 bytes = 60 bytes).
    pub i_block: [u8; 60],
    /// 0x64: File version / generation number (NFS).
    pub i_generation: U32<LE>,
    /// 0x68: Lower 32 bits of the extended attribute block number.
    pub i_file_acl_lo: U32<LE>,
    /// 0x6C: Upper 32 bits of file size (or `i_dir_acl` for directories).
    pub i_size_high: U32<LE>,
    /// 0x70: Obsolete fragment address (always 0 in ext4).
    pub i_obso_faddr: U32<LE>,
    /// 0x74: OS-dependent value 2 (12 bytes).
    pub osd2: [u8; 12],
}

const _: () = assert!(
    core::mem::size_of::<RawInode>() == 128,
    "RawInode must be exactly 128 bytes"
);

bitflags! {
    /// Inode flags from the `i_flags` field at offset 0x20.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct InodeFlags: u32 {
        const SECRM_FL        = 0x0000_0001;
        const UNRM_FL         = 0x0000_0002;
        const COMPR_FL        = 0x0000_0004;
        const SYNC_FL         = 0x0000_0008;
        const IMMUTABLE_FL    = 0x0000_0010;
        const APPEND_FL       = 0x0000_0020;
        const NODUMP_FL       = 0x0000_0040;
        const NOATIME_FL      = 0x0000_0080;
        const DIRTY_FL        = 0x0000_0100;
        const COMPRBLK_FL     = 0x0000_0200;
        const NOCOMPR_FL      = 0x0000_0400;
        const ENCRYPT_FL      = 0x0000_0800;
        const INDEX_FL        = 0x0000_1000;
        const IMAGIC_FL       = 0x0000_2000;
        const JOURNAL_DATA_FL = 0x0000_4000;
        const NOTAIL_FL       = 0x0000_8000;
        const DIRSYNC_FL      = 0x0001_0000;
        const TOPDIR_FL       = 0x0002_0000;
        const HUGE_FILE_FL    = 0x0004_0000;
        const EXTENTS_FL      = 0x0008_0000;
        const VERITY_FL       = 0x0010_0000;
        const EA_INODE_FL     = 0x0020_0000;
        // EOFBLOCKS_FL: legacy "blocks past EOF in tail" hint.
        // Removed from active kernel use ~Linux 4.x but preserved on
        // older filesystems; surfaced for forensic catalog completeness.
        const EOFBLOCKS_FL    = 0x0040_0000;
        // SNAPFILE_FL / SNAPFILE_DELETED_FL / SNAPFILE_SHRUNK_FL:
        // out-of-tree ext4 snapshot patch (paired with
        // `RoCompatFeatures::HAS_SNAPSHOT`). Not interpreted.
        const SNAPFILE_FL          = 0x0100_0000;
        // DAX_FL: filesystem-DAX (Direct Access) hint on regular files.
        const DAX_FL               = 0x0200_0000;
        const SNAPFILE_DELETED_FL  = 0x0400_0000;
        const SNAPFILE_SHRUNK_FL   = 0x0800_0000;
        const INLINE_DATA_FL  = 0x1000_0000;
        const PROJINHERIT_FL  = 0x2000_0000;
        const CASEFOLD_FL     = 0x4000_0000;
    }
}

/// File type mask for the upper 4 bits of `i_mode`.
///
/// Bit values mirror `include/uapi/linux/stat.h`. Kept private to the
/// crate; consumers should use the typed `ExtInode::is_*` accessors or
/// the `ExtFileKind` enum returned by `ExtInode::kind()`.
const S_IFMT: u16 = 0xF000;
const S_IFIFO: u16 = 0x1000;
const S_IFCHR: u16 = 0x2000;
const S_IFDIR: u16 = 0x4000;
const S_IFBLK: u16 = 0x6000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
const S_IFSOCK: u16 = 0xC000;

/// Classification of an inode's POSIX file type.
///
/// Mirrors `include/uapi/linux/stat.h` `S_IF*` values via the upper four
/// bits of `i_mode`. The `Unknown` variant retains the raw mode for any
/// bit pattern the kernel may add in future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtFileKind {
    /// FIFO / named pipe (`S_IFIFO`).
    Fifo,
    /// Character device node (`S_IFCHR`).
    CharacterDevice,
    /// Directory (`S_IFDIR`).
    Directory,
    /// Block device node (`S_IFBLK`).
    BlockDevice,
    /// Regular file (`S_IFREG`).
    RegularFile,
    /// Symbolic link (`S_IFLNK`).
    Symlink,
    /// Unix-domain socket (`S_IFSOCK`).
    Socket,
    /// Mode bits that don't match any defined `S_IF*` value.
    Unknown,
}

/// Decoded device-node identifier (`rdev`) for character/block devices.
///
/// Major/minor are returned as `u32` to preserve the full 32-bit kernel
/// `dev_t` range (12-bit major + 20-bit minor in the "new" encoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtDeviceId {
    /// Major device number (12 bits in the new encoding, 8 bits in old).
    pub major: u32,
    /// Minor device number (20 bits in the new encoding, 8 bits in old).
    pub minor: u32,
}

/// Maximum inline bytes stored in `i_block` for files and symlinks.
const INLINE_I_BLOCK_MAX: u64 = 60;

/// Compact inline-data state for an inode.
///
/// All variants are zero-cost. Overflow inodes store a byte range
/// into `ibody_xattr_data` rather than a separate heap allocation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum InlineDataState {
    /// Not an inline inode (no `INLINE_DATA_FL`).
    None,
    /// Inline content fits entirely in `i_block` — no overflow needed.
    ShortOnly,
    /// Overflow bytes located within `ibody_xattr_data` at the given
    /// range. The offset is relative to the start of `ibody_xattr_data`.
    OverflowRange { offset: usize, len: usize },
    /// Overflow was needed but no valid `system.data` was found.
    /// The error is deferred to access time.
    Invalid,
}

/// Presence bits for [`ExtTimestampExtras`] fields.
const TS_CTIME_EXTRA: u8 = 1 << 0;
const TS_MTIME_EXTRA: u8 = 1 << 1;
const TS_ATIME_EXTRA: u8 = 1 << 2;
const TS_CRTIME_BASE: u8 = 1 << 3;
const TS_CRTIME_EXTRA: u8 = 1 << 4;

/// Compact inline storage for extended inode timestamp fields.
///
/// Parsed once during [`Ext::inode()`] and stored in [`ExtInode`].
/// The `present` bitmask tracks which fields were actually available
/// on disk (gated by `i_extra_isize` thresholds and buffer bounds).
#[derive(Clone, Copy, Debug, Default)]
struct ExtTimestampExtras {
    present: u8,
    ctime_extra: u32,
    mtime_extra: u32,
    atime_extra: u32,
    crtime_base: u32,
    crtime_extra: u32,
}

/// Parsed inode handle with a reference back to the parent [`Ext`].
///
/// Created by [`Ext::inode()`]. Provides accessors for metadata, file
/// type, timestamps, and the raw block mapping array.
pub struct ExtInode<'e> {
    ext: &'e Ext,
    pub(crate) number: u32,
    raw: RawInode,
    size: u64,
    flags: InodeFlags,
    ts_extras: ExtTimestampExtras,
    inline_state: InlineDataState,
    checksum_state: crate::checksum::ChecksumState,
    ibody_xattr_data: Option<Box<[u8]>>,
    xattr_block: u64,
}

impl core::fmt::Debug for ExtInode<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtInode")
            .field("number", &self.number)
            .field("mode", &self.raw.i_mode.get())
            .field("size", &self.size)
            .field("flags", &self.flags)
            .field("links_count", &self.raw.i_links_count.get())
            .finish()
    }
}

impl ExtInode<'_> {
    /// Construct an `ExtInode` from a raw inode for unit tests.
    ///
    /// Uses a static dummy `Ext` so callers cannot exercise I/O paths.
    /// Only available in test builds; keeps the production API surface clean.
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(raw: RawInode, number: u32) -> Self {
        use crate::ext::Ext;
        let flags = InodeFlags::from_bits_retain(raw.i_flags.get());
        let size = u64::from(raw.i_size_lo.get()) | (u64::from(raw.i_size_high.get()) << 32);
        Self {
            ext: Ext::dummy_for_test(),
            number,
            raw,
            size,
            flags,
            ts_extras: ExtTimestampExtras::default(),
            inline_state: InlineDataState::None,
            checksum_state: crate::checksum::ChecksumState::Unknown,
            ibody_xattr_data: None,
            xattr_block: 0,
        }
    }

    /// Raw `i_mode` value (file type + permissions).
    #[must_use]
    pub fn mode(&self) -> u16 {
        self.raw.i_mode.get()
    }

    /// Logical file size in bytes (combined from lower and upper halves).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this inode is a directory (`S_IFDIR`).
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.mode() & S_IFMT == S_IFDIR
    }

    /// Whether this inode is a regular file (`S_IFREG`).
    #[must_use]
    pub fn is_regular_file(&self) -> bool {
        self.mode() & S_IFMT == S_IFREG
    }

    /// Whether this inode is a symbolic link (`S_IFLNK`).
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.mode() & S_IFMT == S_IFLNK
    }

    /// Whether this inode is a FIFO / named pipe (`S_IFIFO`).
    #[must_use]
    pub fn is_fifo(&self) -> bool {
        self.mode() & S_IFMT == S_IFIFO
    }

    /// Whether this inode is a character device node (`S_IFCHR`).
    #[must_use]
    pub fn is_character_device(&self) -> bool {
        self.mode() & S_IFMT == S_IFCHR
    }

    /// Whether this inode is a block device node (`S_IFBLK`).
    #[must_use]
    pub fn is_block_device(&self) -> bool {
        self.mode() & S_IFMT == S_IFBLK
    }

    /// Whether this inode is a Unix-domain socket (`S_IFSOCK`).
    #[must_use]
    pub fn is_socket(&self) -> bool {
        self.mode() & S_IFMT == S_IFSOCK
    }

    /// Whether this inode has the per-directory casefold flag
    /// (`EXT4_CASEFOLD_FL`). Always `false` for non-directory inodes
    /// (the kernel only sets the bit on directories).
    #[must_use]
    pub fn is_casefolded(&self) -> bool {
        self.flags.contains(InodeFlags::CASEFOLD_FL)
    }

    /// Whether this inode has the per-directory or per-file encryption
    /// flag (`EXT4_ENCRYPT_FL`).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.flags.contains(InodeFlags::ENCRYPT_FL)
    }

    /// Classified POSIX file type (`include/uapi/linux/stat.h` `S_IF*`).
    #[must_use]
    pub fn kind(&self) -> ExtFileKind {
        match self.mode() & S_IFMT {
            S_IFIFO => ExtFileKind::Fifo,
            S_IFCHR => ExtFileKind::CharacterDevice,
            S_IFDIR => ExtFileKind::Directory,
            S_IFBLK => ExtFileKind::BlockDevice,
            S_IFREG => ExtFileKind::RegularFile,
            S_IFLNK => ExtFileKind::Symlink,
            S_IFSOCK => ExtFileKind::Socket,
            _ => ExtFileKind::Unknown,
        }
    }

    /// Decoded device-node identifier for character/block device inodes.
    ///
    /// Mirrors `fs/ext4/inode.c:5508-5513` and `include/linux/kdev_t.h`
    /// (`old_decode_dev`/`new_decode_dev`):
    ///
    /// ```text
    /// if (raw_inode->i_block[0])
    ///     init_special_inode(inode, inode->i_mode,
    ///        old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
    /// else
    ///     init_special_inode(inode, inode->i_mode,
    ///        new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
    /// ```
    ///
    /// Returns `None` for non-device inodes; never errors at the byte
    /// level because every 32-bit word is a valid encoding under the
    /// kernel rule.
    #[must_use]
    pub fn device_id(&self) -> Option<ExtDeviceId> {
        if !(self.is_character_device() || self.is_block_device()) {
            return None;
        }
        let block0 = read_u32_le(&self.raw.i_block, 0);
        let (major, minor) = if block0 != 0 {
            // include/linux/kdev_t.h:
            //   old_decode_dev(u16 val) {
            //       return MKDEV((val >> 8) & 255, val & 255);
            //   }
            // C passes `le32_to_cpu(i_block[0])` and the function
            // signature truncates to u16, so only the low 16 bits
            // participate.
            let val = (block0 & 0xFFFF) as u16;
            (u32::from((val >> 8) & 0xff), u32::from(val & 0xff))
        } else {
            // include/linux/kdev_t.h:
            //   new_decode_dev(u32 dev) {
            //       unsigned major = (dev & 0xfff00) >> 8;
            //       unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
            //   }
            let dev = read_u32_le(&self.raw.i_block, 4);
            let major = (dev & 0xf_ff00) >> 8;
            let minor = (dev & 0xff) | ((dev >> 12) & 0xf_ff00);
            (major, minor)
        };
        Some(ExtDeviceId { major, minor })
    }

    /// Inode flags (extents, encryption, inline data, etc).
    pub(crate) fn flags(&self) -> InodeFlags {
        self.flags
    }

    /// Raw 60-byte block mapping array (`i_block[15]`).
    pub(crate) fn i_block(&self) -> [u8; 60] {
        self.raw.i_block
    }

    /// Hard link count.
    #[must_use]
    pub fn links_count(&self) -> u16 {
        self.raw.i_links_count.get()
    }

    /// Last access time.
    #[must_use]
    pub fn atime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_ATIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_atime.get(), self.ts_extras.atime_extra)
        } else {
            base_timestamp(self.raw.i_atime.get())
        }
    }

    /// Last inode change time (metadata modification).
    #[must_use]
    pub fn ctime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_CTIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_ctime.get(), self.ts_extras.ctime_extra)
        } else {
            base_timestamp(self.raw.i_ctime.get())
        }
    }

    /// Last data modification time.
    #[must_use]
    pub fn mtime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_MTIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_mtime.get(), self.ts_extras.mtime_extra)
        } else {
            base_timestamp(self.raw.i_mtime.get())
        }
    }

    /// Deletion time (0 if the file has not been deleted).
    #[must_use]
    pub fn dtime(&self) -> ExtTimestamp {
        base_timestamp(self.raw.i_dtime.get())
    }

    /// Raw `i_dtime` field value as a little-endian u32.
    ///
    /// The kernel dual-uses this field: as a Unix-seconds deletion time
    /// when the inode is deleted, or as the next-inode pointer while the
    /// inode is on the legacy orphan list (`s_last_orphan` chain). Use
    /// `dtime()` for the timestamp interpretation; this accessor returns
    /// the raw value for consumers that need the pointer interpretation.
    pub(crate) fn raw_i_dtime(&self) -> u32 {
        self.raw.i_dtime.get()
    }

    /// File creation (birth) time.
    ///
    /// Returns `None` when the inode lacks extended timestamp fields
    /// (e.g. 128-byte ext2 inodes or when `i_extra_isize` is too small).
    /// Returns base-only precision when `i_crtime` is present but
    /// `i_crtime_extra` is not (`i_extra_isize` in 20..23).
    #[must_use]
    pub fn crtime(&self) -> Option<ExtTimestamp> {
        if self.ts_extras.present & TS_CRTIME_BASE != 0 {
            if self.ts_extras.present & TS_CRTIME_EXTRA != 0 {
                Some(decode_extended_timestamp(
                    self.ts_extras.crtime_base,
                    self.ts_extras.crtime_extra,
                ))
            } else {
                Some(base_timestamp(self.ts_extras.crtime_base))
            }
        } else {
            None
        }
    }
}

/// Bytes-level setter for the `EA_INODE` refcount. Encodes
/// `(refcount >> 32) as u32` into `i_ctime` (offset 0x0C) and
/// `refcount as u32` into `osd1` (offset 0x24, the `l_i_version` field).
///
/// Intended for use by `orphan::mutator` when patching inode scratch.
/// The first 128 bytes of the inode slot hold the base layout, which
/// contains both fields. Callers must pass a slice covering at least
/// the first 0x28 bytes.
///
/// Panics if `inode_bytes.len() < 0x28`.
pub(crate) fn set_ea_inode_refcount_bytes(inode_bytes: &mut [u8], refcount: u64) {
    assert!(
        inode_bytes.len() >= 0x28,
        "inode bytes must cover at least the first 0x28 bytes"
    );
    let encoded = refcount.to_le_bytes();
    inode_bytes[0x0C..0x10].copy_from_slice(&encoded[4..]);
    inode_bytes[0x24..0x28].copy_from_slice(&encoded[..4]);
}

fn validate_ea_inode_size(ea_inum: u32, actual_size: u64, expected_size: u32) -> Result<usize> {
    if actual_size != u64::from(expected_size) {
        return Err(ExtError::InvalidInode {
            inode: ea_inum,
            reason: "EA inode i_size does not match e_value_size",
        });
    }

    usize::try_from(expected_size).map_err(|_| ExtError::InvalidInode {
        inode: ea_inum,
        reason: "EA inode value size exceeds addressable memory",
    })
}

impl Ext {
    /// Read and parse an inode by number.
    ///
    /// Inode numbers are 1-based. Inode 0 is never valid. Returns
    /// [`ExtError::InodeOutOfRange`] if `ino` is 0 or exceeds the
    /// filesystem's total inode count.
    ///
    /// # Errors
    ///
    /// Returns an I/O error, [`ExtError::InodeOutOfRange`], or
    /// [`ExtError::InvalidInode`] when the inode table location or record is
    /// invalid.
    pub fn inode<T: Read + Seek>(&self, fs: &mut T, ino: u32) -> Result<ExtInode<'_>> {
        if ino == 0 || ino > self.inodes_count {
            return Err(ExtError::InodeOutOfRange { inode: ino });
        }

        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let group_index = usize::try_from(group).map_err(|_| ExtError::InvalidGroupDescriptor {
            group,
            reason: "group index exceeds addressable memory",
        })?;
        let table_block = self
            .group_descs
            .get(group_index)
            .ok_or(ExtError::InvalidGroupDescriptor {
                group,
                reason: "group descriptor is absent",
            })?
            .inode_table;
        let offset = table_block * u64::from(self.block_size)
            + u64::from(index) * u64::from(self.inode_size);

        fs.seek(SeekFrom::Start(offset))?;
        let mut inode_buf = vec![0u8; usize::from(self.inode_size)];
        fs.read_exact(&mut inode_buf)?;

        let raw =
            *RawInode::ref_from_bytes(&inode_buf[..128]).map_err(|_| ExtError::InvalidInode {
                inode: ino,
                reason: "too short",
            })?;

        let size = u64::from(raw.i_size_lo.get()) | (u64::from(raw.i_size_high.get()) << 32);

        let flags = InodeFlags::from_bits_retain(raw.i_flags.get());

        let extra_isize = inode_extra_isize(&inode_buf, self.inode_size);

        let ts_extras = parse_timestamp_extras(&inode_buf, self.inode_size);

        let ibody_xattr_data: Option<Box<[u8]>> = {
            let xattr_start = 128 + usize::from(extra_isize);
            if xattr_start + 4 <= inode_buf.len() {
                let magic = read_u32_le(&inode_buf, xattr_start);
                if magic == 0xEA02_0000 {
                    Some(inode_buf[xattr_start..].into())
                } else {
                    None
                }
            } else {
                None
            }
        };

        let inline_state = if flags.contains(InodeFlags::INLINE_DATA_FL) {
            if size <= INLINE_I_BLOCK_MAX {
                InlineDataState::ShortOnly
            } else {
                let required = usize::try_from(size)
                    .map_err(|_| ExtError::InvalidInlineData { inode: ino })?
                    - 60;
                match &ibody_xattr_data {
                    Some(ibody) => match crate::inline_xattr::find_system_data_range(ibody, ino) {
                        Ok(Some((offset, len))) if len >= required => {
                            InlineDataState::OverflowRange { offset, len }
                        }
                        _ => InlineDataState::Invalid,
                    },
                    None => InlineDataState::Invalid,
                }
            }
        } else {
            InlineDataState::None
        };

        let has_checksum_hi = self.inode_size > 128 && extra_isize >= 4;
        let checksum_state = match self.checksum_seed {
            Some(seed) => crate::checksum::verify_inode(
                seed,
                ino,
                raw.i_generation.get(),
                &inode_buf,
                has_checksum_hi,
            ),
            None => crate::checksum::ChecksumState::Unknown,
        };

        let xattr_block = {
            let lo = u64::from(raw.i_file_acl_lo.get());
            let hi = if inode_buf.len() >= 0x78 {
                u64::from(read_u16_le(&inode_buf, 0x76))
            } else {
                0
            };
            (hi << 32) | lo
        };

        Ok(ExtInode {
            ext: self,
            number: ino,
            raw,
            size,
            flags,
            ts_extras,
            inline_state,
            checksum_state,
            ibody_xattr_data,
            xattr_block,
        })
    }
}

/// Read a little-endian u16 from `buf` at `offset`.
pub(crate) fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    let bytes: [u8; 2] = [buf[offset], buf[offset + 1]];
    u16::from_le_bytes(bytes)
}

/// Read a little-endian u32 from `buf` at `offset`.
pub(crate) fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    u32::from_le_bytes(bytes)
}

/// Parse extended timestamp fields from the raw inode buffer.
///
/// Each field is gated by the kernel's `EXT4_FITS_IN_INODE` rule:
///   `offsetof(field) + sizeof(field) <= 128 + i_extra_isize`
///
/// Per-field minimum `i_extra_isize`:
/// - `>= 8`:  `ctime_extra`  (0x84..0x88)
/// - `>= 12`: `mtime_extra`  (0x88..0x8C)
/// - `>= 16`: `atime_extra`  (0x8C..0x90)
/// - `>= 20`: `crtime`       (0x90..0x94)
/// - `>= 24`: `crtime_extra` (0x94..0x98)
///
/// Fields are only decoded when both their threshold is met AND the
/// absolute byte range fits within the inode buffer.
fn parse_timestamp_extras(inode_buf: &[u8], inode_size: u16) -> ExtTimestampExtras {
    let mut extras = ExtTimestampExtras::default();

    // Extended fields only exist when inode_size > 128
    if inode_size <= 128 || inode_buf.len() < 130 {
        return extras;
    }

    let extra_isize = inode_extra_isize(inode_buf, inode_size) as usize;

    // Guard: reject extra_isize that extends beyond the actual buffer
    if 128 + extra_isize > inode_buf.len() {
        return extras;
    }

    // i_ctime_extra at 0x84..0x88: needs i_extra_isize >= 8
    if extra_isize >= 8 && inode_buf.len() >= 0x88 {
        extras.ctime_extra = read_u32_le(inode_buf, 0x84);
        extras.present |= TS_CTIME_EXTRA;
    }

    // i_mtime_extra at 0x88..0x8C: needs i_extra_isize >= 12
    if extra_isize >= 12 && inode_buf.len() >= 0x8C {
        extras.mtime_extra = read_u32_le(inode_buf, 0x88);
        extras.present |= TS_MTIME_EXTRA;
    }

    // i_atime_extra at 0x8C..0x90: needs i_extra_isize >= 16
    if extra_isize >= 16 && inode_buf.len() >= 0x90 {
        extras.atime_extra = read_u32_le(inode_buf, 0x8C);
        extras.present |= TS_ATIME_EXTRA;
    }

    // i_crtime at 0x90..0x94: needs i_extra_isize >= 20
    if extra_isize >= 20 && inode_buf.len() >= 0x94 {
        extras.crtime_base = read_u32_le(inode_buf, 0x90);
        extras.present |= TS_CRTIME_BASE;
    }

    // i_crtime_extra at 0x94..0x98: needs i_extra_isize >= 24
    if extra_isize >= 24 && inode_buf.len() >= 0x98 {
        extras.crtime_extra = read_u32_le(inode_buf, 0x94);
        extras.present |= TS_CRTIME_EXTRA;
    }

    extras
}

fn inode_extra_isize(inode_buf: &[u8], inode_size: u16) -> u16 {
    if inode_size > 128 && inode_buf.len() >= 130 {
        read_u16_le(inode_buf, 0x80)
    } else {
        0
    }
}

#[cfg(test)]
#[path = "inode_tests/mod.rs"]
mod tests;
