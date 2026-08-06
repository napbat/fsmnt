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
    /// 0x6C: Upper 32 bits of file size (or i_dir_acl for directories).
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

impl<'e> ExtInode<'e> {
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
    pub fn mode(&self) -> u16 {
        self.raw.i_mode.get()
    }

    /// Logical file size in bytes (combined from lower and upper halves).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this inode is a directory (`S_IFDIR`).
    pub fn is_directory(&self) -> bool {
        self.mode() & S_IFMT == S_IFDIR
    }

    /// Whether this inode is a regular file (`S_IFREG`).
    pub fn is_regular_file(&self) -> bool {
        self.mode() & S_IFMT == S_IFREG
    }

    /// Whether this inode is a symbolic link (`S_IFLNK`).
    pub fn is_symlink(&self) -> bool {
        self.mode() & S_IFMT == S_IFLNK
    }

    /// Whether this inode is a FIFO / named pipe (`S_IFIFO`).
    pub fn is_fifo(&self) -> bool {
        self.mode() & S_IFMT == S_IFIFO
    }

    /// Whether this inode is a character device node (`S_IFCHR`).
    pub fn is_character_device(&self) -> bool {
        self.mode() & S_IFMT == S_IFCHR
    }

    /// Whether this inode is a block device node (`S_IFBLK`).
    pub fn is_block_device(&self) -> bool {
        self.mode() & S_IFMT == S_IFBLK
    }

    /// Whether this inode is a Unix-domain socket (`S_IFSOCK`).
    pub fn is_socket(&self) -> bool {
        self.mode() & S_IFMT == S_IFSOCK
    }

    /// Whether this inode has the per-directory casefold flag
    /// (`EXT4_CASEFOLD_FL`). Always `false` for non-directory inodes
    /// (the kernel only sets the bit on directories).
    pub fn is_casefolded(&self) -> bool {
        self.flags.contains(InodeFlags::CASEFOLD_FL)
    }

    /// Whether this inode has the per-directory or per-file encryption
    /// flag (`EXT4_ENCRYPT_FL`).
    pub fn is_encrypted(&self) -> bool {
        self.flags.contains(InodeFlags::ENCRYPT_FL)
    }

    /// Classified POSIX file type (`include/uapi/linux/stat.h` `S_IF*`).
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
    pub fn links_count(&self) -> u16 {
        self.raw.i_links_count.get()
    }

    /// Last access time.
    pub fn atime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_ATIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_atime.get(), self.ts_extras.atime_extra)
        } else {
            base_timestamp(self.raw.i_atime.get())
        }
    }

    /// Last inode change time (metadata modification).
    pub fn ctime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_CTIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_ctime.get(), self.ts_extras.ctime_extra)
        } else {
            base_timestamp(self.raw.i_ctime.get())
        }
    }

    /// Last data modification time.
    pub fn mtime(&self) -> ExtTimestamp {
        if self.ts_extras.present & TS_MTIME_EXTRA != 0 {
            decode_extended_timestamp(self.raw.i_mtime.get(), self.ts_extras.mtime_extra)
        } else {
            base_timestamp(self.raw.i_mtime.get())
        }
    }

    /// Deletion time (0 if the file has not been deleted).
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
    pub fn checksum_state(&self) -> crate::checksum::ChecksumState {
        self.checksum_state
    }

    /// List all extended attributes on this inode.
    ///
    /// Reads from both the in-inode (ibody) xattr region and the
    /// external xattr block (if present). EA_INODE entries have their
    /// values resolved from the referenced inode.
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
    /// EA_INODE entries are resolved transparently.
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
    #[cfg(feature = "verity")]
    pub fn verity_descriptor<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<crate::verity::VerityDescriptor>> {
        use crate::io::FsReadSeek;

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
    pub fn posix_acl_access<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<Option<Vec<crate::posix_acl::PosixAclEntry>>> {
        self.decode_posix_acl(fs, "system.posix_acl_access")
    }

    /// Decode `system.posix_acl_default` into typed entries, or `None` if the
    /// xattr is absent. See [`crate::posix_acl::PosixAclEntry`] for entry
    /// semantics.
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
        let size = self.size as usize;

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
        use crate::io::FsReadSeek;
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
        use crate::io::FsReadSeek;
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
        let size = self.size as usize;
        let mut file = self.open_ea_data_stream()?;
        let mut buf = alloc::vec![0u8; size];
        use crate::io::FsReadSeek;
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

    /// EA_INODE refcount, kernel-overloaded onto the `i_ctime` / `l_i_version` fields.
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

/// Bytes-level setter for the EA_INODE refcount. Encodes
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
    let hi = (refcount >> 32) as u32;
    let lo = refcount as u32;
    inode_bytes[0x0C..0x10].copy_from_slice(&hi.to_le_bytes());
    inode_bytes[0x24..0x28].copy_from_slice(&lo.to_le_bytes());
}

fn validate_ea_inode_size(ea_inum: u32, actual_size: u64, expected_size: u32) -> Result<usize> {
    if actual_size != u64::from(expected_size) {
        return Err(ExtError::InvalidInode {
            inode: ea_inum,
            reason: "EA inode i_size does not match e_value_size",
        });
    }

    Ok(expected_size as usize)
}

impl Ext {
    /// Read and parse an inode by number.
    ///
    /// Inode numbers are 1-based. Inode 0 is never valid. Returns
    /// [`ExtError::InodeOutOfRange`] if `ino` is 0 or exceeds the
    /// filesystem's total inode count.
    pub fn inode<T: Read + Seek>(&self, fs: &mut T, ino: u32) -> Result<ExtInode<'_>> {
        if ino == 0 || ino > self.inodes_count {
            return Err(ExtError::InodeOutOfRange { inode: ino });
        }

        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let table_block = self.group_descs[group as usize].inode_table;
        let offset = table_block * u64::from(self.block_size)
            + u64::from(index) * u64::from(self.inode_size);

        fs.seek(SeekFrom::Start(offset))?;
        let mut inode_buf = vec![0u8; self.inode_size as usize];
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
            let xattr_start = 128 + extra_isize as usize;
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
                let required = size as usize - INLINE_I_BLOCK_MAX as usize;
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
mod tests {
    use super::*;

    #[test]
    fn raw_inode_is_128_bytes() {
        assert_eq!(core::mem::size_of::<RawInode>(), 128);
    }

    #[test]
    fn ea_inode_size_match_accepts_equal_sizes() {
        let size = validate_ea_inode_size(77, 4096, 4096).unwrap();
        assert_eq!(size, 4096);
    }

    #[test]
    fn ea_inode_size_match_rejects_oversized_inode() {
        let err = validate_ea_inode_size(77, 8192, 4096).unwrap_err();
        assert!(matches!(err, ExtError::InvalidInode { inode: 77, .. }));
    }

    #[test]
    fn ea_inode_size_match_rejects_undersized_inode() {
        let err = validate_ea_inode_size(77, 1024, 4096).unwrap_err();
        assert!(matches!(err, ExtError::InvalidInode { inode: 77, .. }));
    }

    #[test]
    fn inode_flags_known_bits() {
        let flags = InodeFlags::EXTENTS_FL | InodeFlags::HUGE_FILE_FL;
        assert!(flags.contains(InodeFlags::EXTENTS_FL));
        assert!(!flags.contains(InodeFlags::ENCRYPT_FL));
    }

    #[test]
    fn inode_flags_low_priority_catalog_bits() {
        // Catalog inventory bits added for forensic completeness.
        assert_eq!(InodeFlags::EOFBLOCKS_FL.bits(), 0x0040_0000);
        assert_eq!(InodeFlags::SNAPFILE_FL.bits(), 0x0100_0000);
        assert_eq!(InodeFlags::DAX_FL.bits(), 0x0200_0000);
        assert_eq!(InodeFlags::SNAPFILE_DELETED_FL.bits(), 0x0400_0000);
        assert_eq!(InodeFlags::SNAPFILE_SHRUNK_FL.bits(), 0x0800_0000);

        // Round-trip an inode with all five new bits set.
        let raw = 0x0040_0000 | 0x0100_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000;
        let flags = InodeFlags::from_bits_retain(raw);
        assert!(flags.contains(InodeFlags::EOFBLOCKS_FL));
        assert!(flags.contains(InodeFlags::SNAPFILE_FL));
        assert!(flags.contains(InodeFlags::DAX_FL));
        assert!(flags.contains(InodeFlags::SNAPFILE_DELETED_FL));
        assert!(flags.contains(InodeFlags::SNAPFILE_SHRUNK_FL));
    }

    #[test]
    fn inode_flags_unknown_bit_preserved_by_from_bits_retain() {
        // Forensic invariant: unknown future bits round-trip through
        // `from_bits_retain` without being silently dropped.
        let raw = 0x8000_0000u32; // unassigned today
        let flags = InodeFlags::from_bits_retain(raw);
        assert_eq!(flags.bits(), raw);
    }

    #[test]
    fn file_type_constants() {
        assert_eq!(S_IFIFO, 0x1000);
        assert_eq!(S_IFCHR, 0x2000);
        assert_eq!(S_IFDIR, 0x4000);
        assert_eq!(S_IFBLK, 0x6000);
        assert_eq!(S_IFREG, 0x8000);
        assert_eq!(S_IFLNK, 0xA000);
        assert_eq!(S_IFSOCK, 0xC000);
    }

    fn raw_with_mode(mode: u16) -> RawInode {
        RawInode {
            i_mode: U16::new(mode),
            i_uid: U16::new(0),
            i_size_lo: U32::new(0),
            i_atime: U32::new(0),
            i_ctime: U32::new(0),
            i_mtime: U32::new(0),
            i_dtime: U32::new(0),
            i_gid: U16::new(0),
            i_links_count: U16::new(1),
            i_blocks_lo: U32::new(0),
            i_flags: U32::new(0),
            osd1: U32::new(0),
            i_block: [0u8; 60],
            i_generation: U32::new(0),
            i_file_acl_lo: U32::new(0),
            i_size_high: U32::new(0),
            i_obso_faddr: U32::new(0),
            osd2: [0u8; 12],
        }
    }

    fn raw_device(mode: u16, i_block: [u8; 60]) -> RawInode {
        let mut raw = raw_with_mode(mode);
        raw.i_block = i_block;
        raw
    }

    #[test]
    fn ext_inode_kind_dispatches_each_s_if() {
        for (mode, expected) in [
            (S_IFIFO, ExtFileKind::Fifo),
            (S_IFCHR, ExtFileKind::CharacterDevice),
            (S_IFDIR, ExtFileKind::Directory),
            (S_IFBLK, ExtFileKind::BlockDevice),
            (S_IFREG, ExtFileKind::RegularFile),
            (S_IFLNK, ExtFileKind::Symlink),
            (S_IFSOCK, ExtFileKind::Socket),
        ] {
            let inode = ExtInode::from_raw_for_test(raw_with_mode(mode | 0o644), 100);
            assert_eq!(inode.kind(), expected, "mode 0x{mode:04X}");
        }
    }

    #[test]
    fn ext_inode_kind_unknown_for_zero_mode_bits() {
        let inode = ExtInode::from_raw_for_test(raw_with_mode(0), 101);
        assert_eq!(inode.kind(), ExtFileKind::Unknown);
    }

    #[test]
    fn ext_inode_is_helpers_match_kind_for_special_types() {
        let fifo = ExtInode::from_raw_for_test(raw_with_mode(S_IFIFO | 0o600), 1);
        assert!(fifo.is_fifo());
        assert!(!fifo.is_character_device() && !fifo.is_block_device() && !fifo.is_socket());

        let chr = ExtInode::from_raw_for_test(raw_with_mode(S_IFCHR | 0o600), 2);
        assert!(chr.is_character_device());
        assert!(!chr.is_fifo() && !chr.is_block_device() && !chr.is_socket());

        let blk = ExtInode::from_raw_for_test(raw_with_mode(S_IFBLK | 0o600), 3);
        assert!(blk.is_block_device());
        assert!(!blk.is_fifo() && !blk.is_character_device() && !blk.is_socket());

        let sock = ExtInode::from_raw_for_test(raw_with_mode(S_IFSOCK | 0o600), 4);
        assert!(sock.is_socket());
        assert!(!sock.is_fifo() && !sock.is_character_device() && !sock.is_block_device());
    }

    #[test]
    fn device_id_none_for_non_device_inode() {
        for mode in [S_IFIFO, S_IFDIR, S_IFREG, S_IFLNK, S_IFSOCK] {
            let inode = ExtInode::from_raw_for_test(raw_with_mode(mode | 0o644), 10);
            assert!(inode.device_id().is_none(), "mode 0x{mode:04X}");
        }
    }

    #[test]
    fn device_id_old_encoding_low_16_bits() {
        // include/linux/kdev_t.h: old_decode_dev(u16 val) =
        //     MKDEV((val >> 8) & 255, val & 255)
        // raw value 0x0301 => major=3, minor=1 (e.g. /dev/ttyS0 territory)
        let mut blocks = [0u8; 60];
        blocks[0..4].copy_from_slice(&0x0000_0301u32.to_le_bytes());
        let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 11);
        assert_eq!(inode.device_id(), Some(ExtDeviceId { major: 3, minor: 1 }));
    }

    #[test]
    fn device_id_old_encoding_ignores_high_word_and_i_block_1() {
        // fs/ext4/inode.c:5508-5510 — when i_block[0] != 0, only the
        // u16 value of i_block[0] (after C-side truncation) is used;
        // i_block[1] is ignored.
        let mut blocks = [0u8; 60];
        blocks[0..4].copy_from_slice(&0xFFFF_FF55u32.to_le_bytes());
        blocks[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 12);
        assert_eq!(
            inode.device_id(),
            Some(ExtDeviceId {
                major: 0xff,
                minor: 0x55,
            })
        );
    }

    #[test]
    fn device_id_new_encoding_when_i_block0_zero() {
        // include/linux/kdev_t.h: new_encode_dev(dev_t dev) =
        //   (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)
        // For major=0x103, minor=0x301:
        //   (0x01) | (0x103 << 8) | ((0x300) << 12) = 0x01 | 0x10300 | 0x300000
        //   = 0x310301
        let mut blocks = [0u8; 60];
        blocks[0..4].copy_from_slice(&0u32.to_le_bytes());
        blocks[4..8].copy_from_slice(&0x0031_0301u32.to_le_bytes());
        let inode = ExtInode::from_raw_for_test(raw_device(S_IFBLK | 0o660, blocks), 13);
        assert_eq!(
            inode.device_id(),
            Some(ExtDeviceId {
                major: 0x103,
                minor: 0x301,
            })
        );
    }

    #[test]
    fn device_id_new_encoding_full_range() {
        // Max 12-bit major (0xfff) + max 20-bit minor (0xfffff).
        //   (0xff) | (0xfff << 8) | ((0xfff00) << 12)
        //   = 0xff | 0xfff00 | 0xfff00000 = 0xffff_ffff
        let mut blocks = [0u8; 60];
        blocks[0..4].copy_from_slice(&0u32.to_le_bytes());
        blocks[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 14);
        assert_eq!(
            inode.device_id(),
            Some(ExtDeviceId {
                major: 0xfff,
                minor: 0xfffff,
            })
        );
    }

    #[test]
    fn device_id_new_encoding_zero_both_words_decodes_to_zero() {
        // Both words zero is the "new encoding" branch with rdev=0.
        // Valid byte-level encoding (no malformed case).
        let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o600, [0u8; 60]), 15);
        assert_eq!(inode.device_id(), Some(ExtDeviceId { major: 0, minor: 0 }));
    }

    fn raw_inode_with_flags(flags_bits: u32, mode: u16) -> RawInode {
        RawInode {
            i_mode: U16::new(mode),
            i_uid: U16::new(0),
            i_size_lo: U32::new(0),
            i_atime: U32::new(0),
            i_ctime: U32::new(0),
            i_mtime: U32::new(0),
            i_dtime: U32::new(0),
            i_gid: U16::new(0),
            i_links_count: U16::new(1),
            i_blocks_lo: U32::new(0),
            i_flags: U32::new(flags_bits),
            osd1: U32::new(0),
            i_block: [0u8; 60],
            i_generation: U32::new(0),
            i_file_acl_lo: U32::new(0),
            i_size_high: U32::new(0),
            i_obso_faddr: U32::new(0),
            osd2: [0u8; 12],
        }
    }

    #[test]
    fn is_casefolded_reads_inode_flag() {
        // EXT4_CASEFOLD_FL = 0x4000_0000 (inode.rs:93).
        let dir =
            ExtInode::from_raw_for_test(raw_inode_with_flags(0x4000_0000, S_IFDIR | 0o755), 2);
        assert!(dir.is_casefolded());

        let plain_dir = ExtInode::from_raw_for_test(raw_inode_with_flags(0, S_IFDIR | 0o755), 3);
        assert!(!plain_dir.is_casefolded());
    }

    #[test]
    fn is_encrypted_reads_inode_flag() {
        // EXT4_ENCRYPT_FL = 0x0000_0800 (inode.rs:80).
        let enc =
            ExtInode::from_raw_for_test(raw_inode_with_flags(0x0000_0800, S_IFREG | 0o644), 42);
        assert!(enc.is_encrypted());

        let plain = ExtInode::from_raw_for_test(raw_inode_with_flags(0, S_IFREG | 0o644), 43);
        assert!(!plain.is_encrypted());
    }

    /// Build a synthetic inode buffer with given extra_isize and
    /// known timestamp extra values at the correct offsets.
    fn make_inode_buf(size: usize, extra_isize: u16) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        if size >= 130 {
            buf[0x80] = (extra_isize & 0xFF) as u8;
            buf[0x81] = (extra_isize >> 8) as u8;
        }
        // Plant known values at extended timestamp offsets
        if size >= 0x8C {
            // ctime_extra = 0x11
            buf[0x84..0x88].copy_from_slice(&0x11u32.to_le_bytes());
            // mtime_extra = 0x22
            buf[0x88..0x8C].copy_from_slice(&0x22u32.to_le_bytes());
        }
        if size >= 0x90 {
            // atime_extra = 0x33
            buf[0x8C..0x90].copy_from_slice(&0x33u32.to_le_bytes());
        }
        if size >= 0x98 {
            // crtime_base = 0x44, crtime_extra = 0x55
            buf[0x90..0x94].copy_from_slice(&0x44u32.to_le_bytes());
            buf[0x94..0x98].copy_from_slice(&0x55u32.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parse_ts_extras_inode_size_128() {
        let buf = make_inode_buf(128, 0);
        let extras = parse_timestamp_extras(&buf, 128);
        assert_eq!(extras.present, 0);
    }

    #[test]
    fn parse_ts_extras_extra_isize_zero() {
        let buf = make_inode_buf(256, 0);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, 0);
    }

    #[test]
    fn parse_ts_extras_extra_isize_7_no_fields() {
        // i_extra_isize=7: ctime_extra needs >=8, so nothing available
        let buf = make_inode_buf(256, 7);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, 0);
    }

    #[test]
    fn parse_ts_extras_extra_isize_8_ctime_only() {
        // i_extra_isize=8: ctime_extra at 0x84..0x88 fits (8>=8),
        // mtime_extra at 0x88..0x8C needs >=12
        let buf = make_inode_buf(256, 8);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, TS_CTIME_EXTRA);
        assert_eq!(extras.ctime_extra, 0x11);
    }

    #[test]
    fn parse_ts_extras_extra_isize_12_ctime_mtime() {
        // i_extra_isize=12: mtime_extra at 0x88..0x8C fits (12>=12)
        let buf = make_inode_buf(256, 12);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, TS_CTIME_EXTRA | TS_MTIME_EXTRA);
        assert_eq!(extras.ctime_extra, 0x11);
        assert_eq!(extras.mtime_extra, 0x22);
    }

    #[test]
    fn parse_ts_extras_extra_isize_15_no_atime() {
        // i_extra_isize=15: atime_extra at 0x8C..0x90 needs >=16
        let buf = make_inode_buf(256, 15);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, TS_CTIME_EXTRA | TS_MTIME_EXTRA);
    }

    #[test]
    fn parse_ts_extras_extra_isize_16_atime() {
        // i_extra_isize=16: atime_extra at 0x8C..0x90 fits (16>=16)
        let buf = make_inode_buf(256, 16);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(
            extras.present,
            TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA
        );
        assert_eq!(extras.atime_extra, 0x33);
    }

    #[test]
    fn parse_ts_extras_extra_isize_19_no_crtime() {
        // i_extra_isize=19: i_crtime at 0x90..0x94 needs >=20
        let buf = make_inode_buf(256, 19);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(
            extras.present,
            TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA
        );
    }

    #[test]
    fn parse_ts_extras_extra_isize_20_crtime_base_only() {
        // i_extra_isize=20: i_crtime at 0x90..0x94 fits (20>=20),
        // i_crtime_extra at 0x94..0x98 needs >=24
        let buf = make_inode_buf(256, 20);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(
            extras.present,
            TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE
        );
        assert_eq!(extras.crtime_base, 0x44);
    }

    #[test]
    fn parse_ts_extras_extra_isize_23_no_crtime_extra() {
        // i_extra_isize=23: i_crtime_extra at 0x94..0x98 needs >=24
        let buf = make_inode_buf(256, 23);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(
            extras.present,
            TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE
        );
    }

    #[test]
    fn parse_ts_extras_extra_isize_24_crtime_full() {
        let buf = make_inode_buf(256, 24);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(
            extras.present,
            TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE | TS_CRTIME_EXTRA
        );
        assert_eq!(extras.crtime_base, 0x44);
        assert_eq!(extras.crtime_extra, 0x55);
    }

    #[test]
    fn parse_ts_extras_buf_too_short_for_claimed_extra() {
        // extra_isize=32 but buffer is only 140 bytes
        let buf = make_inode_buf(140, 32);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, 0);
    }

    #[test]
    fn parse_ts_extras_buf_short_for_claimed_extra_rejects_all() {
        // extra_isize=24 but buffer only 0x90 bytes (128+24=152 > 144).
        // The entire extended region is inconsistent, so no fields parsed.
        let buf = make_inode_buf(0x90, 24);
        let extras = parse_timestamp_extras(&buf, 256);
        assert_eq!(extras.present, 0);
    }

    #[test]
    fn inode_extra_isize_reads_present_value() {
        let buf = make_inode_buf(256, 32);
        assert_eq!(inode_extra_isize(&buf, 256), 32);
    }

    #[test]
    fn inode_extra_isize_returns_zero_for_small_inode() {
        let buf = make_inode_buf(128, 32);
        assert_eq!(inode_extra_isize(&buf, 128), 0);
    }

    #[test]
    fn raw_i_dtime_returns_le_u32_unchanged() {
        let mut raw_bytes = [0u8; 128];
        // i_dtime at offset 0x14 = 0x1234_5678
        raw_bytes[0x14..0x18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let raw: &RawInode = zerocopy::FromBytes::ref_from_bytes(&raw_bytes).unwrap();
        assert_eq!(raw.i_dtime.get(), 0x1234_5678);
    }

    #[test]
    fn ea_inode_refcount_reads_i_ctime_high_u32_and_osd1_low_u32() {
        // i_ctime at 0x0C..0x10 = 0x1234_5678 (high 32 bits of refcount).
        // osd1 at 0x24..0x28 = 0xABCD_EF01 (low 32 bits, l_i_version).
        // Expected refcount = 0x1234_5678_ABCD_EF01.
        let mut bytes = [0u8; 128];
        bytes[0x0C..0x10].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&0xABCD_EF01u32.to_le_bytes());
        let raw: RawInode = *zerocopy::FromBytes::ref_from_bytes(&bytes).unwrap();
        let inode = ExtInode::from_raw_for_test(raw, 0);
        assert_eq!(inode.ea_inode_refcount(), 0x1234_5678_ABCD_EF01u64);
    }

    #[test]
    fn set_ea_inode_refcount_bytes_writes_i_ctime_high_and_osd1_low() {
        let mut bytes = [0u8; 256];
        set_ea_inode_refcount_bytes(&mut bytes, 0x0000_0001_DEAD_BEEFu64);
        // i_ctime at 0x0C..0x10: high 32 bits = 0x0000_0001
        assert_eq!(&bytes[0x0C..0x10], &0x0000_0001u32.to_le_bytes());
        // osd1 at 0x24..0x28: low 32 bits = 0xDEAD_BEEF
        assert_eq!(&bytes[0x24..0x28], &0xDEAD_BEEFu32.to_le_bytes());
    }

    #[test]
    fn set_ea_inode_refcount_bytes_round_trips_through_reader() {
        let mut bytes = [0u8; 256];
        set_ea_inode_refcount_bytes(&mut bytes, 0xCAFEBABE_12345678u64);
        let raw: RawInode = *zerocopy::FromBytes::ref_from_bytes(&bytes[..128]).unwrap();
        let inode = ExtInode::from_raw_for_test(raw, 0);
        assert_eq!(inode.ea_inode_refcount(), 0xCAFEBABE_12345678u64);
    }

    /// EA inode 536 in ext4.img is the backing store for ea_inode_file's
    /// user.big_value xattr (e_value_inum = 536). It is referenced exactly once,
    /// so its on-disk refcount — packed as (i_ctime << 32) | osd1 — must be 1.
    ///
    /// This test pins the i_ctime + osd1 field choice against future regressions;
    /// the synthetic byte tests above cannot catch a wrong-offset bug because they
    /// exercise both encode and decode through the same offsets.
    ///
    /// Note: inode 536 (not 535) because multiblock.bin (added for truncate
    /// fixtures) was inserted before sparse_file in the ext4.img tree, shifting
    /// all inodes allocated after that point by one.
    #[test]
    fn ea_inode_refcount_reads_1_for_fixture_ea_inode_536() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = crate::ext::Ext::new(&mut cursor).expect("open ext4.img");
        // Inode 536 is the EA inode backing ea_inode_file's big_value xattr.
        // It has EA_INODE_FL and is referenced once, so refcount must be 1.
        let ea_inode = ext.inode(&mut cursor, 536).expect("read EA inode 536");
        assert_eq!(
            ea_inode.ea_inode_refcount(),
            1,
            "EA inode 536 refcount must be 1 (referenced once by ea_inode_file)"
        );
    }
}
