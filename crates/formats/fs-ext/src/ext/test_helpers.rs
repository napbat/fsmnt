use super::*;

impl Ext {
    /// Reads the legacy orphan-chain head directly from the superblock.
    #[cfg(test)]
    pub(crate) fn read_last_orphan<T: Read + Seek>(fs: &mut T) -> crate::error::Result<u32> {
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
            fscrypt_keys: crate::fscrypt::FscryptKeystore::default(),
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
            fscrypt_keys: crate::fscrypt::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }
}
