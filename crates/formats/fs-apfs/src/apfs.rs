//! The top-level [`Apfs`] container handle.
//!
//! [`Apfs::new`] performs the APFS mount sequence — block-zero superblock →
//! latest valid checkpoint → container object map — and enumerates the
//! container's volumes. Following the reader-as-parameter pattern shared with
//! the other filesystem crates, the handle holds parsed metadata only; every
//! read takes `&mut T: Read + Seek`.
//!
//! Apple File System Reference, `04-container.md`.

use alloc::vec;
use alloc::vec::Vec;

use crate::checkpoint::{latest_checkpoint, read_block};
use crate::container::{NX_MINIMUM_BLOCK_SIZE, NxSuperblock};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::omap::Omap;
use crate::types::Oid;
use crate::volume::ApfsSuperblock;

/// A mounted APFS container.
#[derive(Debug, Clone)]
pub struct Apfs {
    /// The container superblock of the latest valid checkpoint.
    superblock: NxSuperblock,
    /// The container object map, used to resolve volume superblocks.
    omap: Omap,
}

impl Apfs {
    /// Mounts an APFS container from a reader positioned at the start of the
    /// container.
    ///
    /// Reads the block-zero superblock to locate the checkpoint ring, selects
    /// the latest valid checkpoint, and parses the container object map.
    ///
    /// # Errors
    ///
    /// Returns an [`ApfsError`] if the image is not APFS, is truncated, or has
    /// no valid checkpoint.
    pub fn new<T: Read + Seek>(reader: &mut T) -> Result<Self> {
        // Block zero holds a copy of the container superblock. Read it at the
        // minimum block size — `nx_block_size` lies well within the first
        // 4 KiB — to learn the container's real block size.
        reader.seek(SeekFrom::Start(0))?;
        let mut probe = vec![0u8; NX_MINIMUM_BLOCK_SIZE as usize];
        reader.read_exact(&mut probe)?;
        let block_zero = NxSuperblock::parse(&probe)?;

        let checkpoint = latest_checkpoint(reader, &block_zero)?;
        let superblock = checkpoint.superblock;

        // The container object map is a physical object, read by its address.
        let omap_block = read_block(reader, superblock.block_size, superblock.omap_oid.0)?;
        let omap = Omap::parse(&omap_block)?;

        Ok(Self { superblock, omap })
    }

    /// The container's block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    /// The total number of blocks in the container.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.superblock.block_count
    }

    /// The container's UUID.
    #[must_use]
    pub fn uuid(&self) -> [u8; 16] {
        self.superblock.uuid
    }

    /// The number of volumes in the container.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.superblock.fs_oids.len()
    }

    /// The transaction identifier of the mounted checkpoint.
    ///
    /// Volume object maps are read as of this transaction.
    #[must_use]
    pub fn transaction_xid(&self) -> crate::types::Xid {
        self.superblock.xid
    }

    /// The virtual object identifiers of the container's volumes.
    #[must_use]
    pub fn volume_oids(&self) -> &[Oid] {
        &self.superblock.fs_oids
    }

    /// Reads and parses the volume superblock at `index`.
    ///
    /// The volume's virtual object identifier is resolved through the
    /// container object map as of the checkpoint's transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::NotFound`] for an out-of-range index or a volume
    /// with no object-map entry, or propagates parsing and I/O errors.
    pub fn volume<T: Read + Seek>(&self, reader: &mut T, index: usize) -> Result<ApfsSuperblock> {
        let fs_oid = *self
            .superblock
            .fs_oids
            .get(index)
            .ok_or(ApfsError::NotFound { what: "volume" })?;

        let mapping = self
            .omap
            .resolve(
                reader,
                self.superblock.block_size,
                fs_oid,
                self.superblock.xid,
            )?
            .ok_or(ApfsError::NotFound {
                what: "volume superblock mapping",
            })?;
        let address = mapping.paddr.as_block().ok_or(ApfsError::Malformed {
            structure: "omap_val_t",
            reason: "volume superblock address is negative",
        })?;
        let block = read_block(reader, self.superblock.block_size, address)?;
        ApfsSuperblock::parse(&block)
    }

    /// Reads and parses every volume superblock in the container.
    ///
    /// # Errors
    ///
    /// Propagates the first error from [`Apfs::volume`].
    pub fn volumes<T: Read + Seek>(&self, reader: &mut T) -> Result<Vec<ApfsSuperblock>> {
        (0..self.volume_count())
            .map(|index| self.volume(reader, index))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::checksum::fletcher64;
    use crate::object::{OBJ_EPHEMERAL, OBJ_PHYSICAL, OBJ_VIRTUAL};
    use fsmnt_testkit::Cursor;

    const BLK: usize = 4096;

    fn seal(block: &mut [u8]) {
        let csum = fletcher64(&block[8..]);
        block[..8].copy_from_slice(&csum.to_le_bytes());
    }

    /// A container superblock with one volume, sealed for the checkpoint scan.
    fn nx_superblock(xid: u64, omap_oid: u64, fs_oid0: u64) -> Vec<u8> {
        nx_superblock_with(xid, omap_oid, &[fs_oid0], &[0u8; 16])
    }

    /// A container superblock with the given volume oids and uuid, sealed.
    fn nx_superblock_with(xid: u64, omap_oid: u64, fs_oids: &[u64], uuid: &[u8; 16]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x10..0x18].copy_from_slice(&xid.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&(OBJ_EPHEMERAL | 0x01).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&0x4253_584Eu32.to_le_bytes()); // NXSB
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x28..0x30].copy_from_slice(&500u64.to_le_bytes()); // nx_block_count
        b[0x48..0x58].copy_from_slice(uuid); // nx_uuid
        b[0x68..0x6C].copy_from_slice(&1u32.to_le_bytes()); // nx_xp_desc_blocks
        b[0x70..0x78].copy_from_slice(&1i64.to_le_bytes()); // nx_xp_desc_base
        b[0x88..0x8C].copy_from_slice(&0u32.to_le_bytes()); // nx_xp_desc_index
        b[0x8C..0x90].copy_from_slice(&1u32.to_le_bytes()); // nx_xp_desc_len
        b[0xA0..0xA8].copy_from_slice(&omap_oid.to_le_bytes()); // nx_omap_oid
        b[0xB4..0xB8].copy_from_slice(&100u32.to_le_bytes()); // nx_max_file_systems
        for (i, oid) in fs_oids.iter().enumerate() {
            let off = 0xB8 + i * 8;
            b[off..off + 8].copy_from_slice(&oid.to_le_bytes());
        }
        seal(&mut b);
        b
    }

    /// A container object-map block whose mapping tree is at `tree_oid`.
    fn omap_block(tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes()); // OMAP
        b[0x30..0x38].copy_from_slice(&tree_oid.to_le_bytes()); // om_tree_oid
        b
    }

    /// A single-entry object-map B-tree: `(vol_oid, xid) -> vol_paddr`.
    fn omap_tree(vol_oid: u64, xid: u64, vol_paddr: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes()); // ROOT|LEAF|FIXED
        b[0x24..0x28].copy_from_slice(&1u32.to_le_bytes()); // btn_nkeys
        b[0x2A..0x2C].copy_from_slice(&4u16.to_le_bytes()); // table_space.len
        let key_area = BTN_DATA_OFFSET + 4;
        b[BTN_DATA_OFFSET..BTN_DATA_OFFSET + 2].copy_from_slice(&0u16.to_le_bytes()); // k off
        b[BTN_DATA_OFFSET + 2..BTN_DATA_OFFSET + 4].copy_from_slice(&16u16.to_le_bytes()); // v off
        b[key_area..key_area + 8].copy_from_slice(&vol_oid.to_le_bytes());
        b[key_area + 8..key_area + 16].copy_from_slice(&xid.to_le_bytes());
        let value_end = BLK - BTREE_INFO_SIZE;
        b[value_end - 16 + 4..value_end - 16 + 8].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[value_end - 16 + 8..value_end - 16 + 16].copy_from_slice(&vol_paddr.to_le_bytes());
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes()); // bt_key_size
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes()); // bt_val_size
        b
    }

    /// A volume superblock block named `name`.
    fn volume_sb(name: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_VIRTUAL | 0x0D).to_le_bytes()); // FS
        b[0x20..0x24].copy_from_slice(&0x4253_5041u32.to_le_bytes()); // APSB
        b[0x2C0..0x2C0 + name.len()].copy_from_slice(name);
        b
    }

    /// Assembles the standard five-block test container.
    fn container() -> Cursor<Vec<u8>> {
        let mut data = Vec::new();
        data.extend(nx_superblock(10, 2, 100)); // block 0: block-zero copy
        data.extend(nx_superblock(10, 2, 100)); // block 1: checkpoint superblock
        data.extend(omap_block(3)); // block 2: container omap
        data.extend(omap_tree(100, 7, 4)); // block 3: omap B-tree
        data.extend(volume_sb(b"TestVolume")); // block 4: volume superblock
        Cursor::new(data)
    }

    #[test]
    fn mounts_a_container_and_reports_geometry() {
        let mut reader = container();
        let apfs = Apfs::new(&mut reader).unwrap();
        assert_eq!(apfs.block_size(), 4096);
        assert_eq!(apfs.block_count(), 500);
        assert_eq!(apfs.volume_count(), 1);
        assert_eq!(apfs.volume_oids(), &[Oid(100)]);
    }

    #[test]
    fn enumerates_the_volume_superblock() {
        let mut reader = container();
        let apfs = Apfs::new(&mut reader).unwrap();
        let volume = apfs.volume(&mut reader, 0).unwrap();
        assert_eq!(volume.name, "TestVolume");

        let all = apfs.volumes(&mut reader).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "TestVolume");
    }

    #[test]
    fn out_of_range_volume_index_is_a_typed_error() {
        let mut reader = container();
        let apfs = Apfs::new(&mut reader).unwrap();
        assert!(matches!(
            apfs.volume(&mut reader, 5),
            Err(ApfsError::NotFound { .. })
        ));
    }

    #[test]
    fn a_non_apfs_image_fails_to_mount() {
        let mut reader = Cursor::new(vec![0u8; BLK * 2]);
        assert!(Apfs::new(&mut reader).is_err());
    }

    /// Builds the standard five-block container with a custom UUID and a
    /// caller-controlled list of volume oids in the superblock.
    fn container_with(uuid: &[u8; 16], fs_oids: &[u64]) -> Cursor<Vec<u8>> {
        let mut data = Vec::new();
        data.extend(nx_superblock_with(10, 2, fs_oids, uuid));
        data.extend(nx_superblock_with(10, 2, fs_oids, uuid));
        data.extend(omap_block(3));
        data.extend(omap_tree(fs_oids[0], 7, 4));
        data.extend(volume_sb(b"TestVolume"));
        Cursor::new(data)
    }

    #[test]
    fn uuid_returns_the_superblock_uuid_byte_for_byte() {
        // A UUID with no 0x00 or 0x01 bytes — a constant-return mutant of any
        // shape (`[0; 16]` or `[1; 16]`) cannot equal it.
        let uuid = [
            0x42u8, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x20, 0x30,
            0x40, 0x50,
        ];
        let mut reader = container_with(&uuid, &[100]);
        let apfs = Apfs::new(&mut reader).unwrap();
        assert_eq!(apfs.uuid(), uuid);
    }

    #[test]
    fn volume_count_reports_every_populated_fs_oid_slot() {
        // Two non-zero fs_oid entries: volume_count must be 2, not 1 or 0.
        let mut reader = container_with(&[0xAB; 16], &[100, 200]);
        let apfs = Apfs::new(&mut reader).unwrap();
        assert_eq!(apfs.volume_count(), 2);
        assert_eq!(apfs.volume_oids(), &[Oid(100), Oid(200)]);
    }
}
