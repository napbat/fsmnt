use super::{
    DetectedBootSector, ExtBackupSuperblock, ScanHitKind, ScanOptions, ext_superblock_info,
    scan_media,
};
use std::io::Cursor;

const IMAGE_SIZE: usize = 16 << 20;
const FAT_OFFSET: u64 = 1 << 20;
/// Sector count and sector size of the synthetic FAT12 volume.
const FAT_SECTORS: u32 = 2880;
const FAT_SECTOR_SIZE: u32 = 512;

/// Write a minimal but valid FAT12 boot sector.
fn write_fat(media: &mut [u8], offset: u64) {
    let offset = usize::try_from(offset).expect("offset fits");
    let sector = &mut media[offset..offset + 512];
    sector[0x00..0x03].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    sector[0x03..0x0b].copy_from_slice(b"mkfs.fat");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 1;
    sector[0x0e..0x10].copy_from_slice(&1_u16.to_le_bytes());
    sector[0x10] = 2;
    sector[0x11..0x13].copy_from_slice(&224_u16.to_le_bytes());
    sector[0x13..0x15].copy_from_slice(&2880_u16.to_le_bytes());
    sector[0x15] = 0xf0;
    sector[0x16..0x18].copy_from_slice(&9_u16.to_le_bytes());
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

/// Write a sector that ends in `55 AA` and carries one partition entry.
fn write_mbr(media: &mut [u8], offset: u64, boot_indicator: u8, start_lba: u32, sectors: u32) {
    let offset = usize::try_from(offset).expect("offset fits");
    let sector = &mut media[offset..offset + 512];
    sector[446] = boot_indicator;
    sector[450] = 0x83; // Linux
    sector[454..458].copy_from_slice(&start_lba.to_le_bytes());
    sector[458..462].copy_from_slice(&sectors.to_le_bytes());
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

/// Inodes per group every synthetic filesystem here declares, and the
/// revision-0 inode size that goes with leaving `s_rev_level` at zero.
const EXT_INODES_PER_GROUP: u32 = 2048;
const EXT_INODE_SIZE: u32 = 128;

/// Geometry of a synthetic ext filesystem.
struct Ext {
    block_size: u32,
    blocks_count: u32,
    blocks_per_group: u32,
    first_data_block: u32,
    uuid: [u8; 16],
}

impl Ext {
    /// Byte offset of the group `group` superblock copy from the start.
    fn copy_offset(&self, group: u32) -> u64 {
        if group == 0 {
            return 1024;
        }
        u64::from(self.first_data_block + group * self.blocks_per_group)
            * u64::from(self.block_size)
    }

    fn size_bytes(&self) -> u64 {
        u64::from(self.blocks_count) * u64::from(self.block_size)
    }

    /// Byte offset of the group descriptor table from the filesystem start.
    fn descriptor_offset(&self) -> u64 {
        u64::from(self.first_data_block + 1) * u64::from(self.block_size)
    }

    /// Write a superblock copy for block group `group` at `at`.
    fn write_superblock(&self, media: &mut [u8], at: u64, group: u32) {
        let at = usize::try_from(at).expect("offset");
        let sb = &mut media[at..at + 0x160];
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // s_inodes_count
        sb[0x04..0x08].copy_from_slice(&self.blocks_count.to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&self.first_data_block.to_le_bytes());
        let log = self.block_size.trailing_zeros() - 10;
        sb[0x18..0x1c].copy_from_slice(&log.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&self.blocks_per_group.to_le_bytes());
        sb[0x28..0x2c].copy_from_slice(&EXT_INODES_PER_GROUP.to_le_bytes());
        sb[0x38..0x3a].copy_from_slice(&0xef53_u16.to_le_bytes());
        let group = u16::try_from(group).expect("group fits");
        sb[0x5a..0x5c].copy_from_slice(&group.to_le_bytes());
        sb[0x68..0x78].copy_from_slice(&self.uuid);
    }

    /// Block the group-0 descriptor points its inode table at.
    fn inode_table_block(&self) -> u32 {
        self.first_data_block + 4
    }

    /// Byte offset of the root inode from the filesystem start: inode 2 is
    /// the second entry of group 0's inode table.
    fn root_inode_offset(&self) -> u64 {
        self.root_inode_offset_for(self.inode_table_block())
    }

    /// The same, for an inode table the descriptor puts at `table_block`.
    fn root_inode_offset_for(&self, table_block: u32) -> u64 {
        u64::from(table_block) * u64::from(self.block_size) + u64::from(EXT_INODE_SIZE)
    }

    /// Write the group-0 descriptor that turns a superblock at `start` into a
    /// filesystem start. No checksum feature is declared, so the structural
    /// fields alone have to be consistent — which is the point.
    fn write_descriptor(&self, media: &mut [u8], start: u64) {
        self.write_descriptor_at(media, start, self.inode_table_block());
    }

    /// The same, with the inode table put wherever `table_block` says — the
    /// one field a scan now has to follow off the end of the chunk.
    fn write_descriptor_at(&self, media: &mut [u8], start: u64, table_block: u32) {
        let at = usize::try_from(start + self.descriptor_offset()).expect("offset");
        let desc = &mut media[at..at + 32];
        desc[0x00..0x04].copy_from_slice(&(self.first_data_block + 2).to_le_bytes());
        desc[0x04..0x08].copy_from_slice(&(self.first_data_block + 3).to_le_bytes());
        desc[0x08..0x0c].copy_from_slice(&table_block.to_le_bytes());
    }

    /// Write the root inode a mount would read next: a directory with the
    /// links and the size every ext root has, and no deletion time.
    fn write_root_inode(&self, media: &mut [u8], start: u64) {
        let at = usize::try_from(start + self.root_inode_offset()).expect("offset");
        let inode = &mut media[at..at + 128];
        inode[0x00..0x02].copy_from_slice(&0x41ed_u16.to_le_bytes()); // i_mode: drwxr-xr-x
        inode[0x04..0x08].copy_from_slice(&self.block_size.to_le_bytes()); // i_size_lo
        inode[0x1a..0x1c].copy_from_slice(&3_u16.to_le_bytes()); // i_links_count
    }

    /// Write the group `group` superblock copy into `media`, for a
    /// filesystem starting at `start`; the primary brings its descriptor
    /// table and the root inode that table names with it, because between
    /// them that is what makes it a start.
    fn write(&self, media: &mut [u8], start: u64, group: u32) -> u64 {
        let at = start + self.copy_offset(group);
        self.write_superblock(media, at, group);
        if group == 0 {
            self.write_descriptor(media, start);
            self.write_root_inode(media, start);
        }
        at
    }

    /// Write a copy of block 0 at `at` — the primary superblock with some
    /// other block behind it, which is what a journal record looks like.
    fn write_journalled_copy(&self, media: &mut [u8], at: u64) {
        self.write_superblock(media, at + 1024, 0);
        // An all-ones block-allocation bitmap: the commonest thing to find
        // where the descriptor table would be if this were a start.
        let junk = usize::try_from(at + self.descriptor_offset()).expect("offset");
        media[junk..junk + 64].fill(0xFF);
    }

    /// Copy blocks 0 and 1 of the filesystem at `start` to `at`, byte for
    /// byte, and fill the inode table the copied descriptor names with the
    /// all-ones bitmap that is actually there.
    ///
    /// This is the harder journal record: one transaction touching both
    /// blocks writes them adjacently, so the copy carries a real, correctly
    /// checksummed group descriptor table and reads as a filesystem start
    /// for as far as the two blocks go.
    fn write_block_pair(&self, media: &mut [u8], start: u64, at: u64) {
        let pair = usize::try_from(self.descriptor_offset() + u64::from(self.block_size))
            .expect("two blocks");
        let from = usize::try_from(start).expect("offset");
        let to = usize::try_from(at).expect("offset");
        media.copy_within(from..from + pair, to);
        let table = usize::try_from(at + self.root_inode_offset()).expect("offset");
        media[table..table + 128].fill(0xFF);
    }
}

/// The 1 KiB-block filesystem used by most tests: its backups land 1024
/// bytes past a 4 KiB boundary, so the scan finds them by probing the
/// filesystem byte that precedes the copy.
fn small_block_ext() -> Ext {
    Ext {
        block_size: 1024,
        blocks_count: 12288,
        blocks_per_group: 8192,
        first_data_block: 1,
        uuid: [0x11; 16],
    }
}

/// A 9 MiB filesystem whose group 1 — and so its backup superblock — falls
/// inside it, leaving room in a 16 MiB image for copies beyond its end.
fn journalled_ext() -> Ext {
    Ext {
        block_size: 1024,
        blocks_count: 9216,
        blocks_per_group: 8192,
        first_data_block: 1,
        uuid: [0x5a; 16],
    }
}

/// A 4 KiB-block filesystem: its groups, and so its backup superblocks,
/// begin on a stride-aligned boundary.
fn large_block_ext(blocks_count: u32) -> Ext {
    Ext {
        block_size: 4096,
        blocks_count,
        blocks_per_group: 1024,
        first_data_block: 0,
        uuid: [0x77; 16],
    }
}

#[test]
fn a_filesystem_and_its_backup_superblocks_are_found_and_folded() {
    let mut media = vec![0_u8; IMAGE_SIZE];
    write_fat(&mut media, FAT_OFFSET);
    let ext = small_block_ext();
    let start = 4 << 20;
    ext.write(&mut media, start, 0);
    let backup = ext.write(&mut media, start, 1);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 2, "{hits:#?}");
    assert_eq!(hits[0].offset, FAT_OFFSET);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Fat12)
    );
    assert_eq!(
        hits[0].size_bytes,
        Some(u64::from(FAT_SECTORS) * u64::from(FAT_SECTOR_SIZE))
    );

    assert_eq!(hits[1].offset, start);
    assert_eq!(
        hits[1].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(hits[1].size_bytes, Some(ext.size_bytes()));
    assert_eq!(
        hits[1].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: backup,
            group: 1
        }],
        "the backup belongs to the primary, not to a hit of its own"
    );
    assert_eq!(hits[1].mount_offset(), Some(start));
}

#[test]
fn a_backup_on_a_large_block_filesystem_is_found_at_its_own_offset() {
    // Groups start on a block boundary, so with 4 KiB blocks the copy
    // sits *at* a stride-aligned offset rather than 1024 past one.
    let ext = large_block_ext(2048);
    let mut media = vec![0_u8; IMAGE_SIZE];
    let start = 1 << 20;
    ext.write(&mut media, start, 0);
    let backup = ext.write(&mut media, start, 1);
    assert_eq!(backup % 4096, 0, "the copy is stride-aligned itself");

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, start);
    assert_eq!(
        hits[0].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: backup,
            group: 1
        }]
    );
}

#[test]
fn a_backup_without_its_primary_names_the_start_it_implies() {
    let ext = small_block_ext();
    let mut media = vec![0_u8; IMAGE_SIZE];
    let start = 4 << 20;
    let backup = ext.write(&mut media, start, 1);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, backup);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::ExtBackupSuperblock {
            group: 1,
            filesystem_start: Some(start),
            start_before_medium: None,
        }
    );
    assert_eq!(hits[0].size_bytes, Some(ext.size_bytes()));
}

#[test]
fn backups_of_a_filesystem_that_begins_before_the_medium_are_one_hit() {
    // An image carved out of the middle of a filesystem: nothing in it is a
    // start, and every backup agrees on how far back the real one lies.
    let ext = large_block_ext(8192);
    let mut media = vec![0_u8; IMAGE_SIZE];
    let first = 4 << 20;
    let second = 12 << 20;
    ext.write_superblock(&mut media, first, 5);
    ext.write_superblock(&mut media, second, 7);
    let before = ext.copy_offset(5) - first;
    assert_eq!(
        before,
        ext.copy_offset(7) - second,
        "both copies must imply the same start for the fold to be meaningful",
    );

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, first);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::ExtBackupSuperblock {
            group: 5,
            filesystem_start: None,
            start_before_medium: Some(before),
        }
    );
    assert_eq!(
        hits[0].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: second,
            group: 7
        }],
        "the second copy corroborates the first rather than opening a row",
    );
    assert_eq!(
        hits[0].mount_offset(),
        None,
        "there is no offset in this medium to mount",
    );
}

#[test]
fn journalled_copies_of_a_primary_inside_its_filesystem_are_dropped() {
    let ext = journalled_ext();
    let mut media = vec![0_u8; IMAGE_SIZE];
    ext.write(&mut media, 0, 0);
    let backup = ext.write(&mut media, 0, 1);
    for copy in [4 << 20, 5 << 20, 6 << 20] {
        ext.write_journalled_copy(&mut media, copy);
    }

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(
        hits[0].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: backup,
            group: 1
        }]
    );
}

#[test]
fn copies_of_a_primary_outside_any_known_filesystem_are_folded_into_one_run() {
    let ext = journalled_ext();
    let mut media = vec![0_u8; IMAGE_SIZE];
    ext.write(&mut media, 0, 0);
    ext.write(&mut media, 0, 1);
    let copies = [10 << 20, 11 << 20, 12 << 20];
    for copy in copies {
        ext.write_journalled_copy(&mut media, copy);
    }
    assert!(
        copies[0] > ext.size_bytes(),
        "the copies must lie past what the filesystem claims",
    );

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 2, "{hits:#?}");
    assert_eq!(hits[1].offset, copies[0]);
    assert_eq!(
        hits[1].kind,
        ScanHitKind::ExtPrimaryCopies {
            copies: 3,
            last_offset: copies[2],
        }
    );
    assert_eq!(
        hits[1].mount_offset(),
        None,
        "nothing says a filesystem starts where a copy happens to sit",
    );
}

#[test]
fn a_backup_naming_an_unconfirmed_primary_makes_it_mountable() {
    // The other reading of an unconfirmed primary: the start is real and its
    // descriptor table is gone. A backup that computes this very offset as
    // its filesystem's start is what settles it.
    let ext = large_block_ext(4096);
    let mut media = vec![0_u8; IMAGE_SIZE];
    let start = 1 << 20;
    ext.write_journalled_copy(&mut media, start);
    let backup = start + ext.copy_offset(1);
    ext.write_superblock(&mut media, backup, 1);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, start);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::ExtPrimaryCopies {
            copies: 1,
            last_offset: start,
        }
    );
    assert_eq!(
        hits[0].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: backup,
            group: 1
        }]
    );
    assert_eq!(hits[0].mount_offset(), Some(start));
}

#[test]
fn a_journalled_pair_of_blocks_is_a_copy_however_well_its_table_reads() {
    // The false positive the descriptor-table check cannot see: one ext4
    // journal transaction touching block 0 and block 1 records them
    // adjacently, so the copy carries the real filesystem's group descriptor
    // table with it and reads as a start for as far as two blocks go. What
    // separates them is the root inode that table points at, which relative
    // to the copy is somebody else's bytes.
    let ext = large_block_ext(1024);
    let mut media = vec![0_u8; IMAGE_SIZE];
    ext.write(&mut media, 0, 0);
    let journalled = 6 << 20;
    let pair = 7 << 20;
    ext.write_journalled_copy(&mut media, journalled);
    ext.write_block_pair(&mut media, 0, pair);
    let fat = 8 << 20;
    write_fat(&mut media, fat);
    assert!(
        journalled > ext.size_bytes(),
        "the copies have to lie past what the filesystem claims",
    );
    assert!(
        fat > pair && fat < pair + ext.size_bytes(),
        "the FAT has to sit inside the extent the copy claims for itself",
    );

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 3, "{hits:#?}");
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(hits[1].offset, journalled);
    assert_eq!(
        hits[1].kind,
        ScanHitKind::ExtPrimaryCopies {
            copies: 2,
            last_offset: pair,
        },
        "the pair is a copy like any other and folds in with its neighbour",
    );
    assert_eq!(hits[1].mount_offset(), None);
    assert_eq!(hits[2].offset, fat);
    assert_eq!(
        hits[2].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Fat12),
        "a copy claims the size of a filesystem that starts elsewhere, so it suppresses nothing",
    );
}

#[test]
fn a_root_inode_past_the_end_of_the_medium_decides_nothing() {
    // A truncated image whose front is intact: the inode table its
    // descriptor names was simply never acquired. "I could not look" must
    // not read as "not a filesystem", or the one mountable thing in the file
    // disappears.
    let ext = large_block_ext(8192);
    let mut media = vec![0_u8; IMAGE_SIZE];
    ext.write_superblock(&mut media, 1024, 0);
    let far = 6000;
    ext.write_descriptor_at(&mut media, 0, far);

    let length = u64::try_from(media.len()).expect("length");
    assert!(
        ext.root_inode_offset_for(far) > length,
        "the root inode has to fall past the bytes the medium holds",
    );
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, 0);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(hits[0].mount_offset(), Some(0));
}

#[test]
fn a_backup_outranks_a_root_inode_that_reads_wrong() {
    // A start with damage rather than a copy: the descriptor table verifies,
    // a backup superblock computes this very offset as its filesystem's
    // start, and only the root inode disagrees. Three structures against one
    // inode — it stays a filesystem, and `--salvage` is what the damage is
    // for.
    let ext = large_block_ext(2048);
    let mut media = vec![0_u8; IMAGE_SIZE];
    let start = 1 << 20;
    ext.write(&mut media, start, 0);
    let inode = usize::try_from(start + ext.root_inode_offset()).expect("offset");
    media[inode..inode + 128].fill(0xFF);
    let backup = ext.write(&mut media, start, 1);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].offset, start);
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(
        hits[0].backup_superblocks,
        vec![ExtBackupSuperblock {
            offset: backup,
            group: 1
        }]
    );
    assert_eq!(hits[0].mount_offset(), Some(start));
}

#[test]
fn a_boot_signature_over_random_entries_is_not_a_partition_table() {
    let mut media = vec![0_u8; IMAGE_SIZE];
    // A boot indicator no partitioner writes: this sector is file data.
    write_mbr(&mut media, 1 << 20, 0x27, 2048, 4096);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn a_partition_table_whose_entries_hold_up_is_still_reported() {
    let mut media = vec![0_u8; IMAGE_SIZE];
    write_mbr(&mut media, 1 << 20, 0x80, 2048, 4096);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(
        hits[0].kind,
        ScanHitKind::PartitionTable(DetectedBootSector::MbrPartitioned)
    );
    assert_eq!(hits[0].mount_offset(), None);
}

#[test]
fn a_finer_stride_does_not_report_the_same_superblock_twice() {
    let ext = small_block_ext();
    let mut media = vec![0_u8; IMAGE_SIZE];
    let start = 4 << 20;
    ext.write(&mut media, start, 0);
    ext.write(&mut media, start, 1);

    let length = u64::try_from(media.len()).expect("length");
    let options = ScanOptions::new().with_stride(512);
    let hits = scan_media(&mut Cursor::new(media), length, options).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].backup_superblocks.len(), 1, "{hits:#?}");
}

#[test]
fn boot_sectors_inside_a_sized_filesystem_are_not_reported() {
    let ext = Ext {
        block_size: 1024,
        blocks_count: 16384,
        blocks_per_group: 8192,
        first_data_block: 1,
        uuid: [0x33; 16],
    };
    let mut media = vec![0_u8; IMAGE_SIZE];
    ext.write(&mut media, 0, 0);
    // File data that happens to look like a FAT boot sector.
    write_fat(&mut media, 8 << 20);

    let length = u64::try_from(media.len()).expect("length");
    let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(
        hits[0].kind,
        ScanHitKind::Filesystem(DetectedBootSector::Ext)
    );
    assert_eq!(hits[0].size_bytes, Some(ext.size_bytes()));
}

#[test]
fn a_zero_stride_is_refused_rather_than_looping() {
    let options = ScanOptions::new().with_stride(0);
    let result = scan_media(&mut Cursor::new(vec![0_u8; 4096]), 4096, options);
    assert!(result.is_err());
}

#[test]
fn empty_media_produces_no_hits() {
    let hits = scan_media(&mut Cursor::new(Vec::new()), 0, ScanOptions::new()).expect("empty scan");
    assert!(hits.is_empty());
}

#[test]
fn superblock_geometry_matches_the_synthetic_layout() {
    let ext = small_block_ext();
    let mut media = vec![0_u8; 1 << 20];
    ext.write(&mut media, 0, 0);
    let info = ext_superblock_info(&media).expect("primary superblock");
    assert!(info.is_primary());
    assert_eq!(info.size_bytes(), ext.size_bytes());
    assert_eq!(info.copy_offset(), 1024);
    assert_eq!(info.uuid, ext.uuid);
    assert_eq!(info.inodes_per_group, EXT_INODES_PER_GROUP);
    assert_eq!(
        info.inode_size, EXT_INODE_SIZE,
        "revision 0 fixes the inode size rather than storing it",
    );
    assert_eq!(info.group_size_bytes(), 8 << 20);
}
