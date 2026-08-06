use alloc::vec::Vec;
use zerocopy::FromBytes;

use crate::block_group::{GdtLayout, GroupDescriptor, read_group_descriptors};
use crate::checksum::{self, ChecksumState};
use crate::error::{ExtError, Result};
use crate::feature_flags::{
    CompatFeatures, IncompatFeatures, RoCompatFeatures, validate_clean_state,
    validate_parse_features,
};
use crate::io::{Read, Seek, SeekFrom};
use crate::superblock::{
    ExtSuperblockForensics, RawSuperblock, SUPERBLOCK_MAGIC, SUPERBLOCK_OFFSET,
};

/// Compute filesystem size safely, saturating on overflow.
///
/// On a malformed 64-bit superblock with an oversized `blocks_count`, the
/// product may exceed u64::MAX. This function returns u64::MAX instead of
/// panicking (debug) or wrapping (release).
#[inline]
fn size_from(block_size: u32, blocks_count: u64) -> u64 {
    u64::from(block_size).saturating_mul(blocks_count)
}

/// Compute free space safely, saturating on overflow.
///
/// Mirrors [`size_from`]: on a malformed 64-bit filesystem the sum of
/// `free_blocks_count` across groups combined with a 64 KiB block size
/// could exceed u64::MAX. Return u64::MAX instead of panicking or wrapping.
#[inline]
fn free_bytes_from(block_size: u32, free_blocks: u64) -> u64 {
    u64::from(block_size).saturating_mul(free_blocks)
}

/// Parsed ext2/ext3/ext4 filesystem.
///
/// Created via [`Ext::new()`], which reads and validates the superblock
/// and group descriptor table. All subsequent operations take
/// `&mut T: Read + Seek` as a parameter (reader-as-parameter pattern).
#[derive(Debug)]
pub struct Ext {
    pub(crate) inodes_count: u32,
    pub(crate) blocks_count: u64,
    pub(crate) block_size: u32,
    pub(crate) group_count: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) inode_size: u16,
    pub(crate) first_data_block: u32,
    pub(crate) gdt_layout: GdtLayout,
    pub(crate) blocks_per_group: u32,
    pub(crate) cluster_size: u32,
    pub(crate) blocks_per_cluster: u32,
    pub(crate) clusters_per_group: u32,
    pub(crate) backup_bgs: [u32; 2],
    pub(crate) desc_size: u16,
    pub(crate) incompat: IncompatFeatures,
    pub(crate) ro_compat: RoCompatFeatures,
    pub(crate) compat: CompatFeatures,
    pub(crate) journal_inum: u32,
    /// `s_journal_uuid` — the UUID of the external journal device, or
    /// all-zero for an internal-journal (or journal-less) filesystem.
    pub(crate) journal_uuid: [u8; 16],
    pub(crate) orphan_file_inum: u32,
    pub(crate) usr_quota_inum: u32,
    pub(crate) grp_quota_inum: u32,
    pub(crate) prj_quota_inum: u32,
    pub(crate) is_64bit: bool,
    pub(crate) uuid: [u8; 16],
    pub(crate) hash_seed: [u32; 4],
    pub(crate) group_descs: Vec<GroupDescriptor>,
    pub(crate) checksum_seed: Option<u32>,
    pub(crate) superblock_checksum: ChecksumState,
    pub(crate) encoding: u16,
    pub(crate) encoding_flags: u16,
    pub(crate) first_inode: u32,
    pub(crate) s_encrypt_pw_salt: [u8; 16],
    pub(crate) s_encrypt_algos: [u8; 4],
    pub(crate) mmp_block: u64,
    pub(crate) mmp_update_interval: u16,
    pub(crate) forensics: ExtSuperblockForensics,
    #[cfg(feature = "fscrypt")]
    pub(crate) fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore,
}

impl Ext {
    /// Open a filesystem without clean-state gating. Intended as a recovery
    /// or diagnostic entry point.
    ///
    /// Accepts images with `INCOMPAT_RECOVER` or `RO_COMPAT_ORPHAN_PRESENT`
    /// set; surfaces them via [`Self::needs_journal_recovery`] and
    /// [`Self::has_orphan_present`]. The returned [`Ext`] is fully parsed
    /// but is not guaranteed to represent a coherent filesystem state.
    ///
    /// Parse-layer rejects still apply: images with `INCOMPAT_JOURNAL_DEV`
    /// or unknown feature bits still fail.
    pub fn open_lenient<T: Read + Seek>(fs: &mut T) -> Result<Self> {
        Self::open_impl(fs, false, false)
    }

    /// Open a filesystem that stores its journal on an external device
    /// (`INCOMPAT_JOURNAL_DEV`), supplying both the filesystem reader
    /// and the external journal device reader.
    ///
    /// Like [`Self::open_lenient`], this accepts a dirty / recovery
    /// state — an external-journal filesystem is typically opened
    /// precisely to replay that journal. It additionally validates the
    /// journal device's jbd2 superblock UUID against the filesystem's
    /// `s_journal_uuid`; a mismatch fails with [`ExtError::JournalUuidMismatch`].
    ///
    /// The single-reader [`Self::new`] / [`Self::open_lenient`] paths
    /// keep rejecting `INCOMPAT_JOURNAL_DEV` with
    /// [`ExtError::UnsupportedJournalDevice`].
    pub fn open_with_external_journal<T: Read + Seek, J: Read + Seek>(
        fs: &mut T,
        journal: &mut J,
    ) -> Result<Self> {
        let ext = Self::open_impl(fs, false, true)?;
        // Validate the external journal device up front so a UUID
        // mismatch or unreadable journal surfaces at open time, not
        // only when replay is attempted.
        if ext.incompat.contains(IncompatFeatures::JOURNAL_DEV) {
            crate::journal::source::open_external_journal_source(&ext, journal)?;
        }
        Ok(ext)
    }

    /// Open an ext2/ext3/ext4 filesystem from a reader.
    ///
    /// Reads the superblock at byte offset 1024, validates the magic
    /// number and feature flags (including clean-state gating for
    /// `INCOMPAT_RECOVER` and `RO_COMPAT_ORPHAN_PRESENT`), then reads the
    /// full group descriptor table into memory.
    pub fn new<T: Read + Seek>(fs: &mut T) -> Result<Self> {
        Self::open_impl(fs, true, false)
    }

    fn open_impl<T: Read + Seek>(
        fs: &mut T,
        strict: bool,
        permit_journal_dev: bool,
    ) -> Result<Self> {
        fs.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
        let mut buf = [0u8; 1024];
        fs.read_exact(&mut buf)?;

        let sb = RawSuperblock::ref_from_bytes(&buf).map_err(|_| ExtError::UnexpectedEof {
            context: "superblock too short",
            offset: SUPERBLOCK_OFFSET,
        })?;

        let magic = sb.s_magic.get();
        if magic != SUPERBLOCK_MAGIC {
            return Err(ExtError::InvalidMagic { magic });
        }

        let (incompat, ro_compat, compat, inode_size, desc_size) = if sb.s_rev_level.get() == 0 {
            (
                IncompatFeatures::empty(),
                RoCompatFeatures::empty(),
                CompatFeatures::empty(),
                128u16,
                32u16,
            )
        } else {
            let incompat = IncompatFeatures::from_bits_retain(sb.s_feature_incompat.get());
            let ro_compat = RoCompatFeatures::from_bits_retain(sb.s_feature_ro_compat.get());
            let compat = CompatFeatures::from_bits_retain(sb.s_feature_compat.get());

            validate_parse_features(incompat, ro_compat, permit_journal_dev)?;

            let inode_size = sb.s_inode_size.get();
            let desc_size = if incompat.contains(IncompatFeatures::_64BIT) {
                let ds = sb.s_desc_size.get();
                if ds < 64 {
                    return Err(ExtError::InvalidDescriptorSize { size: ds });
                }
                ds
            } else {
                32
            };
            (incompat, ro_compat, compat, inode_size, desc_size)
        };

        let log_block_size = sb.s_log_block_size.get();
        if log_block_size > 6 {
            return Err(ExtError::InvalidBlockSize {
                raw: log_block_size,
            });
        }
        let block_size = 1024u32 << log_block_size;

        if inode_size < 128 || !inode_size.is_power_of_two() || u32::from(inode_size) > block_size {
            return Err(ExtError::InvalidInodeSize { raw: inode_size });
        }

        let blocks_per_group = sb.s_blocks_per_group.get();
        if blocks_per_group == 0 {
            return Err(ExtError::InvalidSuperblock {
                reason: "s_blocks_per_group is zero",
            });
        }

        let log_cluster_size = sb.s_log_cluster_size.get();
        let cluster_size =
            1024u32
                .checked_shl(log_cluster_size)
                .ok_or(ExtError::InvalidSuperblock {
                    reason: "s_log_cluster_size too large",
                })?;
        if cluster_size % block_size != 0 {
            return Err(ExtError::InvalidSuperblock {
                reason: "cluster size is not a multiple of block size",
            });
        }
        let blocks_per_cluster = cluster_size / block_size;

        let clusters_per_group = sb.s_clusters_per_group.get();
        if clusters_per_group == 0 {
            return Err(ExtError::InvalidSuperblock {
                reason: "s_clusters_per_group is zero",
            });
        }

        if ro_compat.contains(RoCompatFeatures::BIGALLOC) {
            let expected = clusters_per_group.checked_mul(blocks_per_cluster);
            if expected != Some(blocks_per_group) {
                return Err(ExtError::InvalidSuperblock {
                    reason: "clusters_per_group * blocks_per_cluster \
                             does not equal blocks_per_group",
                });
            }
        } else {
            if cluster_size != block_size {
                return Err(ExtError::InvalidSuperblock {
                    reason: "cluster size must equal block size \
                             without bigalloc",
                });
            }
            if clusters_per_group != blocks_per_group {
                return Err(ExtError::InvalidSuperblock {
                    reason: "clusters_per_group must equal \
                             blocks_per_group without bigalloc",
                });
            }
        }

        let inodes_per_group = sb.s_inodes_per_group.get();
        if inodes_per_group == 0 {
            return Err(ExtError::InvalidSuperblock {
                reason: "s_inodes_per_group is zero",
            });
        }

        let is_64bit = incompat.contains(IncompatFeatures::_64BIT);
        let blocks_count_hi = if is_64bit {
            sb.s_blocks_count_hi.get()
        } else {
            0
        };
        let blocks_count =
            (u64::from(blocks_count_hi) << 32) | u64::from(sb.s_blocks_count_lo.get());

        let first_data_block = sb.s_first_data_block.get();
        if blocks_count <= u64::from(first_data_block) {
            return Err(ExtError::InvalidSuperblock {
                reason: "blocks_count <= first_data_block",
            });
        }

        let data_blocks = blocks_count - u64::from(first_data_block);
        let group_count = data_blocks.div_ceil(u64::from(blocks_per_group)) as u32;

        // Checksum seed and superblock validation.
        // Only validate when METADATA_CSUM is set AND s_checksum_type == 1
        // (CRC32C). Other algorithm codes are unsupported.
        let has_metadata_csum = ro_compat.contains(RoCompatFeatures::METADATA_CSUM);
        let csum_type_is_crc32c = sb.s_checksum_type == 1;
        let (checksum_seed, superblock_checksum) = if has_metadata_csum && csum_type_is_crc32c {
            let seed = if incompat.contains(IncompatFeatures::CSUM_SEED) {
                sb.s_checksum_seed.get()
            } else {
                checksum::seed_from_uuid(&sb.s_uuid)
            };
            let sb_state = checksum::verify_superblock(&buf);
            (Some(seed), sb_state)
        } else {
            (None, ChecksumState::Unknown)
        };

        let first_meta_bg = if sb.s_rev_level.get() == 0 {
            0
        } else {
            sb.s_first_meta_bg.get()
        };

        let gdt_layout = GdtLayout::from_parts(
            first_data_block,
            block_size,
            blocks_per_group,
            desc_size,
            first_meta_bg,
            incompat.contains(IncompatFeatures::META_BG),
            ro_compat.contains(RoCompatFeatures::SPARSE_SUPER),
            compat.contains(CompatFeatures::SPARSE_SUPER2),
            [sb.s_backup_bgs[0].get(), sb.s_backup_bgs[1].get()],
            group_count,
            sb.s_reserved_gdt_blocks.get(),
        )?;

        let group_descs = read_group_descriptors(fs, &gdt_layout, is_64bit, checksum_seed)?;

        let encoding = sb.s_encoding.get();
        let encoding_flags = sb.s_encoding_flags.get();
        let s_encrypt_pw_salt = sb.s_encrypt_pw_salt;
        let s_encrypt_algos = sb.s_encrypt_algos;

        let ext = Self {
            inodes_count: sb.s_inodes_count.get(),
            blocks_count,
            block_size,
            group_count,
            inodes_per_group,
            inode_size,
            first_data_block,
            gdt_layout,
            blocks_per_group,
            cluster_size,
            blocks_per_cluster,
            clusters_per_group,
            backup_bgs: [sb.s_backup_bgs[0].get(), sb.s_backup_bgs[1].get()],
            desc_size,
            incompat,
            ro_compat,
            compat,
            journal_inum: sb.s_journal_inum.get(),
            journal_uuid: sb.s_journal_uuid,
            orphan_file_inum: sb.s_orphan_file_inum.get(),
            usr_quota_inum: sb.s_usr_quota_inum.get(),
            grp_quota_inum: sb.s_grp_quota_inum.get(),
            prj_quota_inum: sb.s_prj_quota_inum.get(),
            is_64bit,
            uuid: sb.s_uuid,
            hash_seed: [
                sb.s_hash_seed[0].get(),
                sb.s_hash_seed[1].get(),
                sb.s_hash_seed[2].get(),
                sb.s_hash_seed[3].get(),
            ],
            group_descs,
            checksum_seed,
            superblock_checksum,
            encoding,
            encoding_flags,
            // ext2 rev0 superblocks predate s_first_ino as a dynamic
            // field; the first non-reserved inode is fixed to
            // EXT2_GOOD_OLD_FIRST_INO = 11. Mirrors the special-case in
            // the rev0 branch above for `inode_size` / `desc_size`.
            first_inode: if sb.s_rev_level.get() == 0 {
                11
            } else {
                sb.s_first_ino.get()
            },
            s_encrypt_pw_salt,
            s_encrypt_algos,
            mmp_block: sb.s_mmp_block.get(),
            mmp_update_interval: sb.s_mmp_update_interval.get(),
            forensics: ExtSuperblockForensics::from_raw(sb),
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        };
        if strict {
            validate_clean_state(ext.incompat, ext.ro_compat)?;
        }
        Ok(ext)
    }

    /// Block size in bytes (1024, 2048, 4096, ..., up to 65536).
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total size of the filesystem in bytes (`block_size * blocks_count`).
    ///
    /// Mirrors `fs_ntfs::Ntfs::size` — used by the agent-core adapter to
    /// report `TargetFilesystem::total_size()`.
    pub fn size(&self) -> u64 {
        size_from(self.block_size, self.blocks_count)
    }

    /// Total free blocks across all block groups.
    ///
    /// Sums `bg_free_blocks_count` from every group descriptor. Uninitialized
    /// groups (BLOCK_UNINIT) report their full `blocks_per_group` as free,
    /// so no special-case handling is required.
    pub fn free_blocks(&self) -> u64 {
        self.group_descs
            .iter()
            .map(|g| u64::from(g.free_blocks_count))
            .sum()
    }

    /// Total free space in bytes (`free_blocks() * block_size()`), saturating
    /// on the rare malformed-superblock overflow case.
    pub fn free_bytes(&self) -> u64 {
        free_bytes_from(self.block_size, self.free_blocks())
    }

    /// Cluster size in bytes. Equals `block_size` when bigalloc is not enabled.
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Number of filesystem blocks per cluster (1 without bigalloc).
    pub fn blocks_per_cluster(&self) -> u32 {
        self.blocks_per_cluster
    }

    /// On-disk inode size in bytes.
    pub fn inode_size(&self) -> u16 {
        self.inode_size
    }

    /// Number of block groups in the filesystem.
    pub fn group_count(&self) -> u32 {
        self.group_count
    }

    /// 128-bit filesystem UUID.
    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// First non-reserved inode (`s_first_ino`).
    ///
    /// Inodes below this number are reserved for filesystem internals
    /// (root, journal, resize, quota, etc.). Standard ext4 sets this
    /// to 11.
    pub fn first_inode(&self) -> u32 {
        self.first_inode
    }

    /// Forensic-relevant superblock fields: mkfs/mtime/wtime/lastcheck
    /// timestamps, lifetime kilobytes written, error-history records,
    /// mount options, and the error counter. See [`ExtSuperblockForensics`].
    pub fn superblock_forensics(&self) -> &ExtSuperblockForensics {
        &self.forensics
    }

    /// Lifetime kilobytes written counter (`s_kbytes_written`).
    pub fn kbytes_written(&self) -> u64 {
        self.forensics.kbytes_written
    }

    /// Filesystem creation time (`s_mkfs_time` extended to 40 bits).
    pub fn mkfs_time(&self) -> u64 {
        self.forensics.mkfs_time_seconds
    }

    /// Raw mount-options string (`s_mount_opts`, 64 bytes, NUL-padded).
    pub fn mount_opts(&self) -> &[u8; 64] {
        &self.forensics.mount_opts
    }

    /// Whether the filesystem uses 64-bit block addressing.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Whether the GDT uses INCOMPAT_META_BG layout.
    pub fn is_meta_bg(&self) -> bool {
        self.gdt_layout.meta_bg()
    }

    /// Total number of GDT blocks (`group_count.div_ceil(desc_per_block)`).
    pub fn total_desc_blocks(&self) -> u32 {
        self.gdt_layout.total_desc_blocks()
    }

    /// Superblock checksum validation state.
    pub fn superblock_checksum(&self) -> ChecksumState {
        self.superblock_checksum
    }

    /// Per-group descriptor checksum validation states.
    pub fn group_checksums(&self) -> impl ExactSizeIterator<Item = ChecksumState> + '_ {
        self.group_descs.iter().map(|gd| gd.checksum)
    }

    /// Per-group block bitmap block number and free-block counter.
    ///
    /// Each element is `(bitmap_block, free_blocks_count)` for the corresponding
    /// block group. The free-block count is in clusters on bigalloc filesystems
    /// and in blocks on non-bigalloc filesystems.
    #[cfg(test)]
    pub(crate) fn group_block_stats(&self) -> impl ExactSizeIterator<Item = (u64, u32)> + '_ {
        self.group_descs
            .iter()
            .map(|gd| (gd.block_bitmap, gd.free_blocks_count))
    }

    /// Whether the filesystem has a journal (ext3/ext4).
    pub fn has_journal(&self) -> bool {
        self.compat.contains(CompatFeatures::HAS_JOURNAL)
    }

    /// Whether the filesystem requires journal recovery.
    pub fn needs_journal_recovery(&self) -> bool {
        self.incompat.contains(IncompatFeatures::RECOVER)
    }

    /// Whether the journal lives on an external device
    /// (`INCOMPAT_JOURNAL_DEV`). Such filesystems must be opened with
    /// [`Self::open_with_external_journal`].
    pub fn uses_external_journal(&self) -> bool {
        self.incompat.contains(IncompatFeatures::JOURNAL_DEV)
    }

    /// `s_journal_uuid` — the UUID of the external journal device.
    ///
    /// All-zero for an internal-journal or journal-less filesystem.
    pub fn journal_uuid(&self) -> [u8; 16] {
        self.journal_uuid
    }

    /// Whether METADATA_CSUM is enabled (triggers ext4 superblock checksum).
    pub(crate) fn has_metadata_csum(&self) -> bool {
        self.ro_compat.contains(RoCompatFeatures::METADATA_CSUM)
    }

    /// Whether the legacy GDT_CSUM feature is active (CRC16 group-descriptor checksums).
    ///
    /// Mutually exclusive with METADATA_CSUM in practice; callers should prefer
    /// [`Self::has_metadata_csum`] and fall back to this only when that returns false.
    pub(crate) fn has_gdt_csum(&self) -> bool {
        self.ro_compat.contains(RoCompatFeatures::GDT_CSUM)
    }

    /// Whether the filesystem has orphan entries requiring processing.
    pub fn has_orphan_present(&self) -> bool {
        self.ro_compat.contains(RoCompatFeatures::ORPHAN_PRESENT)
    }

    /// Whether the filesystem has a dedicated orphan file (COMPAT_ORPHAN_FILE).
    pub fn has_orphan_file(&self) -> bool {
        self.compat.contains(CompatFeatures::ORPHAN_FILE)
    }

    /// Whether multi-mount protection is enabled (`INCOMPAT_MMP`).
    pub fn has_mmp(&self) -> bool {
        self.incompat.contains(IncompatFeatures::MMP)
    }

    /// MMP block number (`s_mmp_block`). Meaningful only when
    /// [`Self::has_mmp`] is true.
    pub fn mmp_block_number(&self) -> u64 {
        self.mmp_block
    }

    /// MMP poll interval in seconds (`s_mmp_update_interval`).
    pub fn mmp_update_interval(&self) -> u16 {
        self.mmp_update_interval
    }

    /// Read and validate the MMP block, returning a parsed
    /// [`crate::ExtMmpBlock`].
    ///
    /// Returns `Ok(None)` when MMP is not enabled. Returns
    /// `Err(InvalidMmpBlock { .. })` on bad magic. The returned
    /// `checksum` field reports `Valid`/`Invalid` when METADATA_CSUM is
    /// active and `Unknown` otherwise.
    pub fn read_mmp_block<T: Read + Seek>(&self, fs: &mut T) -> Result<Option<crate::ExtMmpBlock>> {
        if !self.has_mmp() {
            return Ok(None);
        }
        if self.mmp_block == 0 {
            return Err(ExtError::InvalidMmpBlock {
                reason: "s_mmp_block is zero",
            });
        }
        let byte_offset = self
            .mmp_block
            .checked_mul(u64::from(self.block_size))
            .ok_or(ExtError::BlockOutOfRange {
                block: self.mmp_block,
            })?;
        fs.seek(SeekFrom::Start(byte_offset))?;
        let mut block = [0u8; 1024];
        fs.read_exact(&mut block)?;
        let parsed = crate::mmp::parse_mmp_block(&block, self.checksum_seed)?;
        Ok(Some(parsed))
    }

    /// Inode number of the user-quota tree file (`s_usr_quota_inum`).
    ///
    /// Zero when the filesystem has no journaled user quota; non-zero when
    /// `RO_COMPAT_QUOTA` is set and a per-user disk-usage tree exists. The
    /// referenced inode holds a vfsv1 quota tree readable via [`Self::quota`].
    pub fn usr_quota_inum(&self) -> u32 {
        self.usr_quota_inum
    }

    /// Inode number of the group-quota tree file (`s_grp_quota_inum`).
    ///
    /// Zero when the filesystem has no journaled group quota; non-zero when
    /// `RO_COMPAT_QUOTA` is set and a per-group disk-usage tree exists.
    pub fn grp_quota_inum(&self) -> u32 {
        self.grp_quota_inum
    }

    /// Inode number of the project-quota tree file (`s_prj_quota_inum`).
    ///
    /// Zero when the filesystem has no project quota; non-zero when
    /// `RO_COMPAT_PROJECT` is set and a per-project disk-usage tree exists.
    pub fn prj_quota_inum(&self) -> u32 {
        self.prj_quota_inum
    }

    /// Whether the filesystem uses clustered allocation (RO_COMPAT_BIGALLOC).
    ///
    /// This method is used by `mutator.rs` tests and future callers.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "gate removed in Task 26; kept for test and future use"
        )
    )]
    pub(crate) fn has_bigalloc(&self) -> bool {
        self.ro_compat.contains(RoCompatFeatures::BIGALLOC)
    }

    /// Inode number of the orphan file (0 when COMPAT_ORPHAN_FILE is clear).
    pub(crate) fn orphan_file_inum(&self) -> u32 {
        self.orphan_file_inum
    }

    /// Metadata checksum seed, when METADATA_CSUM is enabled.
    pub(crate) fn checksum_seed(&self) -> Option<u32> {
        self.checksum_seed
    }

    /// Inode number of the journal file (0 if HAS_JOURNAL is not set).
    pub(crate) fn journal_inum(&self) -> u32 {
        self.journal_inum
    }

    /// Whether directory entries include a file type byte.
    pub(crate) fn has_filetype(&self) -> bool {
        self.incompat.contains(IncompatFeatures::FILETYPE)
    }

    /// Whether the filesystem supports directory indexing (htree).
    pub(crate) fn has_dir_index(&self) -> bool {
        self.compat.contains(CompatFeatures::DIR_INDEX)
    }

    /// Whether the filesystem supports 3-level htree directories.
    pub(crate) fn has_largedir(&self) -> bool {
        self.incompat.contains(IncompatFeatures::LARGEDIR)
    }

    /// HTREE hash seed from the superblock (4 x u32).
    pub(crate) fn hash_seed(&self) -> &[u32; 4] {
        &self.hash_seed
    }

    /// Filename character encoding (`s_encoding`).
    ///
    /// Returns 0 when CASEFOLD is not enabled. UTF-8 is encoding 1.
    pub(crate) fn encoding(&self) -> u16 {
        self.encoding
    }

    /// Raw `s_encoding_flags` value from the superblock.
    ///
    /// Bit 0 (`SB_ENC_STRICT_MODE_FL`, see `include/linux/fs.h:1265`)
    /// signals strict-mode validation of casefolded directory entry
    /// names. Higher bits are reserved.
    pub fn encoding_flags(&self) -> u16 {
        self.encoding_flags
    }

    /// Whether the filesystem has strict-mode UTF-8 encoding enabled
    /// (`SB_ENC_STRICT_MODE_FL`, `include/linux/fs.h:1265`).
    ///
    /// `fs-ext` is a read-only forensic parser and does not reject
    /// non-conforming names; consumers walking casefolded directories
    /// should use [`is_strict_encoding_valid_name`] to detect names
    /// the kernel would have rejected at create time.
    pub fn has_strict_encoding(&self) -> bool {
        // include/linux/fs.h:1265 — SB_ENC_STRICT_MODE_FL = (1 << 0).
        self.encoding_flags & 0x0001 != 0
    }

    /// Superblock `s_encrypt_pw_salt` (16 bytes; zero when fscrypt unused).
    pub fn s_encrypt_pw_salt(&self) -> [u8; 16] {
        self.s_encrypt_pw_salt
    }

    /// Superblock `s_encrypt_algos` (4 bytes; zero when fscrypt unused).
    pub fn s_encrypt_algos(&self) -> [u8; 4] {
        self.s_encrypt_algos
    }

    /// `s_last_orphan` from the superblock — head of the legacy orphan chain.
    ///
    /// Reads directly from the image; returns 0 when the chain is empty.
    /// Used by tests that need to identify the orphan chain head without
    /// going through a full `OrphanReplay` build.
    #[cfg(test)]
    pub(crate) fn last_orphan<T: Read + Seek>(&self, fs: &mut T) -> crate::error::Result<u32> {
        const S_LAST_ORPHAN_OFFSET: u64 = crate::superblock::SUPERBLOCK_OFFSET + 0xE8;
        let mut buf = [0u8; 4];
        fs.seek(SeekFrom::Start(S_LAST_ORPHAN_OFFSET))?;
        fs.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Minimal `Ext` instance for unit tests that construct [`ExtInode`] directly
    /// from raw bytes without I/O. All numeric fields are zero / empty; callers
    /// must not exercise any path that dereferences `group_descs` or does I/O.
    #[cfg(test)]
    pub(crate) fn dummy_for_test() -> &'static Self {
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use alloc::boxed::Box;

        let gdt_layout = GdtLayout::from_parts(
            /* first_data_block */ 0,
            /* block_size */ 4096,
            /* blocks_per_group */ 0,
            /* desc_size */ 64, // any valid value; group_count = 0 so it never reads
            /* first_meta_bg */ 0,
            /* meta_bg */ false,
            /* sparse_super */ false,
            /* sparse_super2 */ false,
            /* backup_bgs */ [0, 0],
            /* group_count */ 0,
            /* reserved_gdt_blocks */ 0,
        )
        .expect("dummy layout must validate");

        // Leak a single allocation for the lifetime of the test process.
        // Static ref avoids the borrow problem of returning a local.
        let ext = Box::new(Self {
            inodes_count: 0,
            blocks_count: 1024,
            block_size: 4096,
            group_count: 0,
            inodes_per_group: 1,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout,
            blocks_per_group: 0,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 0,
            backup_bgs: [0, 0],
            desc_size: 0,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::empty(),
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }

    /// Minimal `Ext` instance for unit tests that need a bigalloc filesystem.
    /// Sets `RO_COMPAT_BIGALLOC`, `blocks_per_cluster = blocks_per_cluster`,
    /// and `cluster_size = block_size * blocks_per_cluster`. All other fields
    /// are zero / empty; callers must not exercise any path that dereferences
    /// `group_descs` or does I/O.
    #[cfg(test)]
    pub(crate) fn dummy_for_test_bigalloc(blocks_per_cluster: u32) -> &'static Self {
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use alloc::boxed::Box;

        let block_size = 4096u32;

        let gdt_layout = GdtLayout::from_parts(
            /* first_data_block */ 0,
            /* block_size */ block_size,
            /* blocks_per_group */ 1024,
            /* desc_size */ 64,
            /* first_meta_bg */ 0,
            /* meta_bg */ false,
            /* sparse_super */ false,
            /* sparse_super2 */ false,
            /* backup_bgs */ [0, 0],
            /* group_count */ 0,
            /* reserved_gdt_blocks */ 0,
        )
        .expect("dummy bigalloc layout must validate");

        // Use a non-zero blocks_per_group so pass 2 of free_allocations can
        // compute group numbers without a divide-by-zero. The empty group_descs
        // vec then causes a bounds-check error (MutatorError::Ext) rather than
        // a panic — which is the expected outcome for negative tests.
        let ext = Box::new(Self {
            inodes_count: 0,
            blocks_count: 1024,
            block_size,
            group_count: 0,
            inodes_per_group: 1,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout,
            blocks_per_group: 1024,
            cluster_size: block_size * blocks_per_cluster,
            blocks_per_cluster,
            clusters_per_group: 0,
            backup_bgs: [0, 0],
            desc_size: 0,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::BIGALLOC,
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }

    /// Register a v1 master key under the operator-supplied descriptor.
    ///
    /// We only support AES-256-XTS content + AES-256-CTS filenames on
    /// v1 policies, both of which require derived keys at least 32 and
    /// 64 bytes respectively. The kernel `derive_key_aes` slices the
    /// master key down to `derived_keysize` bytes, so a master key
    /// shorter than 64 bytes would surface a latent runtime error at
    /// the first content read. Reject undersized keys here so the
    /// caller gets a clear error at registration time instead.
    #[cfg(feature = "fscrypt")]
    pub fn add_fscrypt_v1_key(
        &mut self,
        descriptor: crate::fscrypt::FscryptKeyDescriptor,
        key: crate::fscrypt::FscryptMasterKey,
    ) -> crate::error::Result<()> {
        if key.as_bytes().len() < 64 {
            return Err(crate::error::ExtError::InvalidFscryptPolicy {
                inode: 0,
                reason: "v1 master keys must be at least 64 bytes for AES-256-XTS",
            });
        }
        self.fscrypt_keys.add_v1(descriptor, key);
        Ok(())
    }

    /// Register a v2 master key. Returns its identifier (HKDF-derived).
    #[cfg(feature = "fscrypt")]
    pub fn add_fscrypt_v2_key(
        &mut self,
        key: crate::fscrypt::FscryptMasterKey,
    ) -> crate::fscrypt::FscryptKeyIdentifier {
        self.fscrypt_keys.add_v2(key)
    }

    /// Register a hardware-wrapped v2 master-key blob plus an explicit
    /// unwrap callback.
    ///
    /// Use this when the operator's TEE / Keymaster / Keymint adapter
    /// holds the master key in wrapped form (Android 12+ hardware-bound
    /// fscrypt keys) and the unwrapped bytes can only be reconstructed
    /// via that adapter.
    ///
    /// `identifier` must match the v2 identifier the kernel derives
    /// from the unwrapped key (HKDF-SHA512 context KEY_IDENTIFIER) —
    /// the keystore verifies this on the first lookup and returns
    /// [`crate::error::ExtError::FscryptKeyUnwrapFailed`] on mismatch.
    /// Operators typically know `identifier` from the device's keystore
    /// export.
    ///
    /// `unwrap_key` is invoked at most once per registered key per
    /// session — the keystore caches the unwrapped bytes after the
    /// first lookup. The wrapped blob and any cached unwrapped bytes
    /// zeroize when the keystore drops.
    #[cfg(feature = "fscrypt")]
    pub fn add_fscrypt_v2_wrapped_key(
        &mut self,
        identifier: crate::fscrypt::FscryptKeyIdentifier,
        wrapped_blob: alloc::vec::Vec<u8>,
        unwrapper: alloc::boxed::Box<dyn crate::fscrypt::FscryptKeyUnwrapper>,
    ) {
        self.fscrypt_keys
            .add_v2_wrapped(identifier, wrapped_blob, unwrapper);
    }

    /// Iterate registered v1 descriptors.
    #[cfg(feature = "fscrypt")]
    pub fn fscrypt_v1_descriptors(
        &self,
    ) -> impl Iterator<Item = crate::fscrypt::FscryptKeyDescriptor> + '_ {
        self.fscrypt_keys.iter_v1()
    }

    /// Iterate registered v2 identifiers.
    #[cfg(feature = "fscrypt")]
    pub fn fscrypt_v2_identifiers(
        &self,
    ) -> impl Iterator<Item = crate::fscrypt::FscryptKeyIdentifier> + '_ {
        self.fscrypt_keys.iter_v2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_reports_blocks_times_block_size_on_clean_ext4() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: ext4.img fixture not generated");
            return;
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let expected = u64::from(ext.block_size()) * ext.blocks_count;
        assert_eq!(ext.size(), expected);
        assert!(ext.size() > 0);
    }

    #[test]
    fn size_from_saturates_on_overflow() {
        // Malformed 64-bit superblock: huge block count + 64 KiB blocks would
        // overflow u64. saturating_mul must return u64::MAX instead of panicking
        // (debug) or wrapping (release).
        let size = size_from(65_536, u64::MAX);
        assert_eq!(size, u64::MAX);
    }

    #[test]
    fn size_from_computes_product_when_in_range() {
        assert_eq!(size_from(4096, 100), 409_600);
        assert_eq!(size_from(1024, 0), 0);
        assert_eq!(size_from(0, 1_000_000), 0);
    }

    #[test]
    fn free_blocks_is_positive_and_less_than_total_on_clean_ext4() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: ext4.img fixture not generated");
            return;
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let free = ext.free_blocks();
        assert!(free > 0, "clean fixture must have some free blocks");
        let total_blocks = ext.size() / u64::from(ext.block_size());
        assert!(free < total_blocks, "free_blocks must be less than total");
    }

    #[test]
    fn free_bytes_equals_free_blocks_times_block_size_on_clean_ext4() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: ext4.img fixture not generated");
            return;
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert_eq!(
            ext.free_bytes(),
            ext.free_blocks() * u64::from(ext.block_size())
        );
    }

    #[test]
    fn free_bytes_from_saturates_on_overflow() {
        // Mirror size_from_saturates_on_overflow. 64-bit fs with ~u64::MAX free
        // blocks × 64 KiB would overflow; saturating_mul must return u64::MAX.
        assert_eq!(free_bytes_from(65_536, u64::MAX), u64::MAX);
    }

    #[test]
    fn free_bytes_from_computes_product_when_in_range() {
        assert_eq!(free_bytes_from(4096, 100), 409_600);
        assert_eq!(free_bytes_from(1024, 0), 0);
        assert_eq!(free_bytes_from(0, 1_000_000), 0);
    }

    #[test]
    fn surfaces_encrypt_pw_salt_and_algos_zero_on_unset() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: ext4.img fixture not generated");
            return;
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        // Plain ext4.img has no fscrypt — both fields must be zero.
        assert_eq!(ext.s_encrypt_pw_salt(), [0u8; 16]);
        assert_eq!(ext.s_encrypt_algos(), [0u8; 4]);
    }

    #[test]
    fn classical_ext4_image_reports_no_meta_bg() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: ext4.img fixture not generated");
            return;
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert!(!ext.is_meta_bg(), "ext4.img must not have META_BG");
        assert_eq!(
            ext.total_desc_blocks(),
            ext.group_count()
                .div_ceil(ext.block_size() / u32::from(ext.desc_size)),
            "total_desc_blocks must match group_count.div_ceil(desc_per_block)"
        );
    }

    #[test]
    fn full_mixed_mode_via_first_meta_bg_patch() {
        use fs_common::io::FsReadSeek;

        if !crate::test_support::fixture_available("ext4-meta-bg.img") {
            eprintln!("skipping: ext4-meta-bg.img fixture not generated");
            return;
        }
        let mut bytes = crate::test_support::load_image("ext4-meta-bg.img").into_inner();

        // Patch s_first_meta_bg (offset 0x104 in the superblock at byte 1024)
        // from 0 to 1. With 1 KiB blocks + first_data_block = 1, descriptor
        // block 0's classical and META_BG locations both resolve to block 2,
        // so this exercises the mixed-mode boundary without relocating data.
        let s_first_meta_bg_offset = 1024 + 0x104;
        bytes[s_first_meta_bg_offset..s_first_meta_bg_offset + 4]
            .copy_from_slice(&1u32.to_le_bytes());

        // Recompute the superblock CRC (offset 0x3FC in the SB).
        let sb: &[u8; 1024] = (&bytes[1024..2048]).try_into().unwrap();
        let new_csum = crate::checksum::compute_superblock_csum(sb);
        bytes[1024 + 0x3FC..1024 + 0x400].copy_from_slice(&new_csum.to_le_bytes());

        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open mixed-mode patch");
        assert!(ext.is_meta_bg());
        assert_eq!(ext.gdt_layout.first_meta_bg(), 1);

        // Reuse a subset of the read assertions from the integration test.
        let mut root = ext.root_directory();
        let hello = root
            .lookup(&mut cursor, b"hello.txt")
            .expect("lookup hello");
        let hello_inode = ext
            .inode(&mut cursor, hello.inode_number)
            .expect("hello inode");
        let mut hello_file = hello_inode.open_file().expect("hello file");
        let mut hello_buf = [0u8; 64];
        let n = hello_file
            .read(&mut cursor, &mut hello_buf)
            .expect("read hello");
        assert_eq!(&hello_buf[..n], b"Hello from ext4-meta-bg!\n");
    }
}
