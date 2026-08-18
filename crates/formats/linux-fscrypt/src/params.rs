//! What fscrypt needs to know about the filesystem underneath it.
//!
//! The kernel reaches these three facts through `struct super_block` and
//! its `s_cop` hooks. This crate has no filesystem of its own, so the
//! host passes them in: `fs-ext` fills them from the ext4 superblock,
//! a future f2fs parser from its own.

/// Filesystem-level inputs to fscrypt key and IV derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsParams {
    /// Filesystem block size in bytes — the default fscrypt data-unit
    /// size, and the upper bound on a v2 policy's `log2_data_unit_size`.
    pub block_size: u32,
    /// Filesystem UUID (ext4 `s_uuid`), mixed into the HKDF info of the
    /// `IV_INO_LBLK_64` / `IV_INO_LBLK_32` per-mode keys.
    pub uuid: [u8; 16],
    /// Whether the filesystem guarantees inode numbers never change.
    ///
    /// Kernel `supported_iv_ino_lblk_policy` calls
    /// `sb->s_cop->has_stable_inodes(sb)` and rejects `IV_INO_LBLK_*`
    /// policies when it returns false; ext4 answers from
    /// `EXT4_FEATURE_COMPAT_STABLE_INODES`.
    pub has_stable_inodes: bool,
}

impl FsParams {
    /// `log2` of the block size, as [`crate::policy::validate_supported`]
    /// wants it for the `log2_data_unit_size` bound.
    ///
    /// # Panics
    ///
    /// Never: a `u32`'s trailing-zero count is at most 32.
    #[must_use]
    pub fn block_size_log2(&self) -> u8 {
        u8::try_from(self.block_size.trailing_zeros())
            .expect("a u32 trailing-zero count never exceeds 32")
    }
}
