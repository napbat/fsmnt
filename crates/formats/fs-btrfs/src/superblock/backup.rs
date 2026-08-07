//! Typed superblock root-backup records.

use alloc::vec::Vec;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U64, Unaligned};

use super::{MAX_TREE_LEVELS, MIN_VOLUME_BYTES};

/// Number of historical root records reserved in every Btrfs superblock.
pub(super) const ROOT_BACKUP_COUNT: usize = 4;

/// Exact 168-byte `btrfs_root_backup` disk layout.
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct RawRootBackup {
    pub(crate) tree_root: U64<LE>,
    pub(crate) tree_root_generation: U64<LE>,
    pub(crate) chunk_root: U64<LE>,
    pub(crate) chunk_root_generation: U64<LE>,
    pub(crate) extent_root: U64<LE>,
    pub(crate) extent_root_generation: U64<LE>,
    pub(crate) filesystem_root: U64<LE>,
    pub(crate) filesystem_root_generation: U64<LE>,
    pub(crate) device_root: U64<LE>,
    pub(crate) device_root_generation: U64<LE>,
    pub(crate) checksum_root: U64<LE>,
    pub(crate) checksum_root_generation: U64<LE>,
    pub(crate) total_bytes: U64<LE>,
    pub(crate) bytes_used: U64<LE>,
    pub(crate) num_devices: U64<LE>,
    _unused_64: [U64<LE>; 4],
    pub(crate) tree_root_level: u8,
    pub(crate) chunk_root_level: u8,
    pub(crate) extent_root_level: u8,
    pub(crate) filesystem_root_level: u8,
    pub(crate) device_root_level: u8,
    pub(crate) checksum_root_level: u8,
    _unused_8: [u8; 10],
}

const _: [(); 168] = [(); core::mem::size_of::<RawRootBackup>()];

/// One validated tree pointer stored in a superblock root-backup record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsBackupTreeRoot {
    logical: u64,
    generation: u64,
    level: u8,
}

impl BtrfsBackupTreeRoot {
    /// Logical address of the historical tree root block.
    #[must_use]
    pub const fn logical(self) -> u64 {
        self.logical
    }

    /// Transaction generation expected in the historical root block.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// B-tree level of the historical root block.
    #[must_use]
    pub const fn level(self) -> u8 {
        self.level
    }
}

/// One validated historical root set embedded in a Btrfs superblock.
///
/// Btrfs rotates four records as transactions commit. The newest record
/// normally describes the same root tree as the live superblock, while older
/// records provide read-only recovery points when newer metadata is damaged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsRootBackup {
    slot: usize,
    root_tree: BtrfsBackupTreeRoot,
    chunk_tree: BtrfsBackupTreeRoot,
    extent_tree: Option<BtrfsBackupTreeRoot>,
    filesystem_tree: Option<BtrfsBackupTreeRoot>,
    device_tree: Option<BtrfsBackupTreeRoot>,
    checksum_tree: Option<BtrfsBackupTreeRoot>,
    total_bytes: u64,
    bytes_used: u64,
    num_devices: u64,
}

#[derive(Clone, Copy)]
enum OptionalTreeRoot {
    Missing,
    Present(BtrfsBackupTreeRoot),
    Invalid,
}

struct InvalidOptionalTreeRoot;

impl BtrfsRootBackup {
    /// Physical array slot occupied by this record in the superblock.
    #[must_use]
    pub const fn slot(self) -> usize {
        self.slot
    }

    /// Historical root-tree pointer.
    #[must_use]
    pub const fn root_tree(self) -> BtrfsBackupTreeRoot {
        self.root_tree
    }

    /// Historical chunk-tree pointer recorded with the root tree.
    #[must_use]
    pub const fn chunk_tree(self) -> BtrfsBackupTreeRoot {
        self.chunk_tree
    }

    /// Historical extent-tree pointer, when the record carries one.
    ///
    /// Extent-tree-v2 filesystems intentionally leave this legacy singleton
    /// pointer empty because their extent roots are selected through global
    /// root items.
    #[must_use]
    pub const fn extent_tree(self) -> Option<BtrfsBackupTreeRoot> {
        self.extent_tree
    }

    /// Historical default filesystem-tree pointer, when available.
    #[must_use]
    pub const fn filesystem_tree(self) -> Option<BtrfsBackupTreeRoot> {
        self.filesystem_tree
    }

    /// Historical device-tree pointer, when available.
    #[must_use]
    pub const fn device_tree(self) -> Option<BtrfsBackupTreeRoot> {
        self.device_tree
    }

    /// Historical checksum-tree pointer, when the record carries one.
    ///
    /// Extent-tree-v2 filesystems intentionally leave this legacy singleton
    /// pointer empty because checksum roots are selected through global root
    /// items.
    #[must_use]
    pub const fn checksum_tree(self) -> Option<BtrfsBackupTreeRoot> {
        self.checksum_tree
    }

    /// Filesystem capacity recorded for the historical transaction.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    /// Allocated bytes recorded for the historical transaction.
    #[must_use]
    pub const fn bytes_used(self) -> u64 {
        self.bytes_used
    }

    /// Device count recorded for the historical transaction.
    #[must_use]
    pub const fn num_devices(self) -> u64 {
        self.num_devices
    }
}

pub(super) fn parse_root_backups(
    raw_backups: &[RawRootBackup; ROOT_BACKUP_COUNT],
    sector_size: u32,
    super_generation: u64,
) -> Vec<BtrfsRootBackup> {
    raw_backups
        .iter()
        .enumerate()
        .filter_map(|(slot, raw)| parse_root_backup(raw, slot, sector_size, super_generation))
        .collect()
}

fn parse_root_backup(
    raw: &RawRootBackup,
    slot: usize,
    sector_size: u32,
    super_generation: u64,
) -> Option<BtrfsRootBackup> {
    let root_tree = required_root(
        raw.tree_root.get(),
        raw.tree_root_generation.get(),
        raw.tree_root_level,
        sector_size,
        super_generation,
    )?;
    let chunk_tree = required_root(
        raw.chunk_root.get(),
        raw.chunk_root_generation.get(),
        raw.chunk_root_level,
        sector_size,
        super_generation,
    )?;
    let extent_tree = parse_optional_root(optional_root(
        raw.extent_root.get(),
        raw.extent_root_generation.get(),
        raw.extent_root_level,
        sector_size,
        super_generation,
    ))
    .ok()?;
    let filesystem_tree = parse_optional_root(optional_root(
        raw.filesystem_root.get(),
        raw.filesystem_root_generation.get(),
        raw.filesystem_root_level,
        sector_size,
        super_generation,
    ))
    .ok()?;
    let device_tree = parse_optional_root(optional_root(
        raw.device_root.get(),
        raw.device_root_generation.get(),
        raw.device_root_level,
        sector_size,
        super_generation,
    ))
    .ok()?;
    let checksum_tree = parse_optional_root(optional_root(
        raw.checksum_root.get(),
        raw.checksum_root_generation.get(),
        raw.checksum_root_level,
        sector_size,
        super_generation,
    ))
    .ok()?;
    let total_bytes = raw.total_bytes.get();
    let bytes_used = raw.bytes_used.get();
    let num_devices = raw.num_devices.get();
    if total_bytes < MIN_VOLUME_BYTES || bytes_used > total_bytes || num_devices == 0 {
        return None;
    }

    Some(BtrfsRootBackup {
        slot,
        root_tree,
        chunk_tree,
        extent_tree,
        filesystem_tree,
        device_tree,
        checksum_tree,
        total_bytes,
        bytes_used,
        num_devices,
    })
}

fn required_root(
    logical: u64,
    generation: u64,
    level: u8,
    sector_size: u32,
    super_generation: u64,
) -> Option<BtrfsBackupTreeRoot> {
    if logical == 0
        || generation == 0
        || generation > super_generation
        || level >= MAX_TREE_LEVELS
        || !logical.is_multiple_of(u64::from(sector_size))
    {
        return None;
    }
    Some(BtrfsBackupTreeRoot {
        logical,
        generation,
        level,
    })
}

fn optional_root(
    logical: u64,
    generation: u64,
    level: u8,
    sector_size: u32,
    super_generation: u64,
) -> OptionalTreeRoot {
    if logical == 0 && generation == 0 && level == 0 {
        return OptionalTreeRoot::Missing;
    }
    required_root(logical, generation, level, sector_size, super_generation)
        .map_or(OptionalTreeRoot::Invalid, OptionalTreeRoot::Present)
}

fn parse_optional_root(
    root: OptionalTreeRoot,
) -> core::result::Result<Option<BtrfsBackupTreeRoot>, InvalidOptionalTreeRoot> {
    match root {
        OptionalTreeRoot::Missing => Ok(None),
        OptionalTreeRoot::Present(root) => Ok(Some(root)),
        OptionalTreeRoot::Invalid => Err(InvalidOptionalTreeRoot),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_raw() -> RawRootBackup {
        let mut bytes = [0_u8; core::mem::size_of::<RawRootBackup>()];
        let raw = RawRootBackup::mut_from_bytes(&mut bytes).expect("root-backup layout");
        raw.tree_root = U64::new(0x10_0000);
        raw.tree_root_generation = U64::new(9);
        raw.chunk_root = U64::new(0x20_0000);
        raw.chunk_root_generation = U64::new(8);
        raw.extent_root = U64::new(0x30_0000);
        raw.extent_root_generation = U64::new(9);
        raw.filesystem_root = U64::new(0x40_0000);
        raw.filesystem_root_generation = U64::new(7);
        raw.device_root = U64::new(0x50_0000);
        raw.device_root_generation = U64::new(8);
        raw.checksum_root = U64::new(0x60_0000);
        raw.checksum_root_generation = U64::new(6);
        raw.total_bytes = U64::new(1 << 30);
        raw.bytes_used = U64::new(1 << 20);
        raw.num_devices = U64::new(2);
        *raw
    }

    #[test]
    fn parses_every_typed_tree_pointer() {
        let raw = valid_raw();
        let backup = parse_root_backup(&raw, 3, 4096, 10).expect("valid backup");

        assert_eq!(backup.slot(), 3);
        assert_eq!(backup.root_tree().logical(), 0x10_0000);
        assert_eq!(backup.root_tree().generation(), 9);
        assert_eq!(backup.chunk_tree().generation(), 8);
        assert_eq!(
            backup.extent_tree().expect("extent tree").logical(),
            0x30_0000
        );
        assert_eq!(
            backup.filesystem_tree().expect("filesystem tree").logical(),
            0x40_0000
        );
        assert_eq!(
            backup.device_tree().expect("device tree").logical(),
            0x50_0000
        );
        assert_eq!(
            backup.checksum_tree().expect("checksum tree").logical(),
            0x60_0000
        );
        assert_eq!(backup.total_bytes(), 1 << 30);
        assert_eq!(backup.bytes_used(), 1 << 20);
        assert_eq!(backup.num_devices(), 2);
    }

    #[test]
    fn accepts_extent_tree_v2_empty_legacy_roots() {
        let mut raw = valid_raw();
        raw.extent_root = U64::new(0);
        raw.extent_root_generation = U64::new(0);
        raw.checksum_root = U64::new(0);
        raw.checksum_root_generation = U64::new(0);

        let backup = parse_root_backup(&raw, 0, 4096, 10).expect("valid backup");
        assert_eq!(backup.extent_tree(), None);
        assert_eq!(backup.checksum_tree(), None);
    }

    #[test]
    fn rejects_misaligned_future_and_partial_roots() {
        let mut misaligned = valid_raw();
        misaligned.tree_root = U64::new(0x10_0001);
        assert!(parse_root_backup(&misaligned, 0, 4096, 10).is_none());

        let mut future = valid_raw();
        future.tree_root_generation = U64::new(11);
        assert!(parse_root_backup(&future, 0, 4096, 10).is_none());

        let mut partial = valid_raw();
        partial.extent_root_generation = U64::new(0);
        assert!(parse_root_backup(&partial, 0, 4096, 10).is_none());
    }

    #[test]
    fn rejects_empty_and_impossible_geometry_records() {
        let bytes = [0_u8; core::mem::size_of::<RawRootBackup>()];
        let empty = RawRootBackup::ref_from_bytes(&bytes).expect("root-backup layout");
        assert!(parse_root_backup(empty, 0, 4096, 10).is_none());

        let mut invalid = valid_raw();
        invalid.bytes_used = U64::new(invalid.total_bytes.get() + 1);
        assert!(parse_root_backup(&invalid, 0, 4096, 10).is_none());
    }
}
