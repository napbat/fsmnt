use fs_common::iter::{FsTryIterator, FsTryIteratorType};
use fs_common::traverse::{EntryKind, FsDirEntry, FsDirectory, FsId};

use crate::dir_entry::{FatAttributes, FatDirEntries, FatDirEntry};
use crate::error::{FatError, Result};
use crate::fat::Fat;
use crate::file::FatFile;
use crate::io::{Read, Seek};

/// A FAT directory handle that implements [`FsDirectory`].
///
/// Wraps a [`FatFile`] that has been verified to be a directory.
#[derive(Clone, Debug)]
pub struct FatDirectory<'n> {
    file: FatFile<'n>,
}

impl<'n> FatDirectory<'n> {
    /// Creates a directory handle from a [`FatFile`].
    ///
    /// Returns `Err(FatError::NotADirectory)` if the file is not a
    /// directory.
    pub fn new(file: FatFile<'n>) -> Result<Self> {
        if !file.is_directory() {
            return Err(FatError::NotADirectory);
        }
        Ok(Self { file })
    }

    /// Returns the underlying [`FatFile`].
    pub fn into_inner(self) -> FatFile<'n> {
        self.file
    }
}

impl<'n, R: Read + Seek> FsDirectory<R> for FatDirectory<'n> {
    type Error = FatError;
    type EntryIter = FatDirectoryIter<'n>;

    fn entries(&mut self, _r: &mut R) -> Result<FatDirectoryIter<'n>> {
        let inner = self.file.dir_entries()?;
        Ok(FatDirectoryIter { inner })
    }

    fn id(&self) -> Option<FsId> {
        // FAT12/16 root has no cluster (fixed location) — use 0
        // as a stable ID so walk_dir seeds the seen set correctly.
        Some(FsId(self.file.first_cluster().map_or(0, u64::from)))
    }
}

/// Iterator adapter that wraps [`FatDirEntries`] for the [`FsDirectory`]
/// trait.
///
/// Yields [`FatDirectoryEntry`] items that carry the [`Fat`] reference
/// needed for directory traversal.
pub struct FatDirectoryIter<'n> {
    inner: FatDirEntries<'n>,
}

impl<'n> FsTryIteratorType for FatDirectoryIter<'n> {
    type Error = FatError;
    type Item<'a> = FatDirectoryEntry<'n>;
}

impl<'n, R: Read + Seek> FsTryIterator<R> for FatDirectoryIter<'n> {
    fn try_next(&mut self, r: &mut R) -> Result<Option<FatDirectoryEntry<'n>>> {
        let fat = self.inner.fat();
        loop {
            match self.inner.next(r) {
                Some(Ok(entry)) => {
                    // Skip `.` and `..` — they are FAT navigation aids,
                    // not real children. Exposing them lets walk_dir
                    // escape the requested subtree via `..`.
                    if entry.is_dot_or_dotdot() {
                        continue;
                    }
                    return Ok(Some(FatDirectoryEntry { entry, fat }));
                }
                Some(Err(e)) => return Err(e),
                None => return Ok(None),
            }
        }
    }
}

/// A FAT directory entry paired with a [`Fat`] reference, implementing
/// [`FsDirEntry`].
///
/// The `Fat` reference is needed for [`open_dir`](FsDirEntry::open_dir)
/// to construct child directory handles.
pub struct FatDirectoryEntry<'n> {
    entry: FatDirEntry,
    fat: &'n Fat,
}

impl<'n> FatDirectoryEntry<'n> {
    /// Returns a reference to the underlying [`FatDirEntry`].
    pub fn inner(&self) -> &FatDirEntry {
        &self.entry
    }
}

impl<'n, R: Read + Seek> FsDirEntry<R> for FatDirectoryEntry<'n> {
    type Error = FatError;
    type Dir = FatDirectory<'n>;

    fn kind(&self) -> EntryKind {
        if self.entry.is_directory() {
            EntryKind::Directory
        } else if self.entry.attributes().contains(FatAttributes::VOLUME_ID) {
            EntryKind::Other
        } else {
            EntryKind::File
        }
    }

    fn name_bytes(&self) -> &[u8] {
        // Returns the 8.3 short name bytes (11 bytes, CP437-encoded).
        // LFN (UTF-16LE) is available via `inner().long_name_utf16()`
        // but cannot be reinterpreted as `&[u8]` without unsafe code.
        self.entry.short_name().as_slice()
    }

    fn id(&self) -> Option<FsId> {
        let cluster = self.entry.first_cluster();
        if cluster == 0 {
            // Cluster 0 means root. On FAT32 the root lives at
            // root_cluster, so map 0 → root_cluster to match the
            // ID returned by FatDirectory::id() for the root dir.
            let root = self.fat.root_cluster();
            Some(FsId(u64::from(root)))
        } else {
            Some(FsId(u64::from(cluster)))
        }
    }

    fn open_dir(&self, _r: &mut R) -> Result<Option<Self::Dir>> {
        if !self.entry.is_directory() {
            return Ok(None);
        }
        let cluster = self.entry.first_cluster();
        let file = if cluster == 0 {
            // Cluster 0 means root on both FAT12/16 and FAT32.
            // Delegate to root_directory() which picks the right
            // representation (fixed-area vs cluster-chain).
            self.fat.root_directory()
        } else {
            FatFile::new(self.fat, Some(cluster), true, 0)
        };
        Ok(Some(FatDirectory { file }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir_entry::DirFileEntryData;
    use alloc::collections::BTreeSet;
    use alloc::string::String;
    use alloc::vec::Vec;
    use fs_common::traverse::walk_dir;
    use std::io::Cursor;
    use zerocopy::FromBytes;

    /// Verify that the trait bounds required by `walk_dir` are
    /// satisfied for our types. This is a compile-time check only.
    #[allow(dead_code)]
    fn assert_fs_directory_bound<'n, R: Read + Seek>()
    where
        FatDirectory<'n>: FsDirectory<R>,
    {
    }

    /// Verify that `FatDirectoryEntry` satisfies `FsDirEntry` with
    /// the correct `Dir` associated type.
    #[allow(dead_code)]
    fn assert_fs_dir_entry_bound<'n, R: Read + Seek>()
    where
        FatDirectoryEntry<'n>: FsDirEntry<R, Dir = FatDirectory<'n>>,
    {
    }

    #[test]
    fn fat_directory_entry_kind() {
        // Create a regular file entry
        let mut raw = [0u8; 32];
        raw[0..8].copy_from_slice(b"TEST    ");
        raw[8..11].copy_from_slice(b"TXT");
        raw[11] = 0x20; // ARCHIVE attribute
        let data = DirFileEntryData::read_from_bytes(&raw).unwrap();
        let dir_entry = FatDirEntry::new(data);

        // Fat reference isn't used for kind()/name_bytes()/id()
        // so we can test those without a real Fat.
        // We can't construct FatDirectoryEntry without a &Fat,
        // but we can test FatDirEntry accessors.
        assert!(!dir_entry.is_directory());
        assert!(!dir_entry.is_volume_id());
        assert_eq!(dir_entry.short_name()[0], b'T');
    }

    /// `FatDirectoryEntry::name_bytes` must expose the entry's exact 11-byte
    /// short name. Catches `name_bytes -> &[u8]` replaced with
    /// `Vec::leak(Vec::new())`, `Vec::leak(vec![0])`, or `Vec::leak(vec![1])`.
    #[test]
    fn fat_directory_entry_name_bytes_returns_full_short_name() {
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let mut root_dir = FatDirectory::new(fat.root_directory()).expect("is directory");
        let mut iter = root_dir.entries(&mut cur).expect("entries");

        let mut found_names: Vec<[u8; 11]> = Vec::new();
        while let Some(entry) = iter.try_next(&mut cur).expect("next") {
            let bytes = <FatDirectoryEntry<'_> as FsDirEntry<Cursor<Vec<u8>>>>::name_bytes(&entry);
            assert_eq!(bytes.len(), 11, "name_bytes must be exactly 11 bytes");
            let mut name = [0u8; 11];
            name.copy_from_slice(bytes);
            found_names.push(name);
        }

        assert_eq!(found_names.len(), 2, "root has SUBDIR and ROOT_F.TXT");
        // SUBDIR padded with spaces to 11 bytes.
        assert!(
            found_names.iter().any(|n| n == b"SUBDIR     "),
            "expected SUBDIR short name in {found_names:?}",
        );
        // ROOT_F.TXT: 8 + 3 = "ROOT_F  TXT" (no dot, 8-char base padded).
        assert!(
            found_names.iter().any(|n| n == b"ROOT_F  TXT"),
            "expected ROOT_F.TXT short name in {found_names:?}",
        );
    }

    // ---------------------------------------------------------------
    // Helpers for building minimal in-memory FAT images
    // ---------------------------------------------------------------

    /// Write a 32-byte directory entry into `img` at byte offset `off`.
    fn write_dir_entry(
        img: &mut [u8],
        off: usize,
        name: &[u8; 11],
        attrs: u8,
        cluster: u32,
        size: u32,
    ) {
        img[off..off + 11].copy_from_slice(name);
        img[off + 0x0B] = attrs;
        // first_cluster_high at offset 0x14
        img[off + 0x14..off + 0x16].copy_from_slice(&(cluster >> 16).to_le_bytes()[..2]);
        // first_cluster_low at offset 0x1A
        img[off + 0x1A..off + 0x1C].copy_from_slice(&(cluster as u16).to_le_bytes());
        // file_size at offset 0x1C
        img[off + 0x1C..off + 0x20].copy_from_slice(&size.to_le_bytes());
    }

    /// Build a minimal FAT16 image.
    ///
    /// Layout (sector_size=512, 1 sector/cluster):
    ///   Sector 0  (0x0000): Boot sector
    ///   Sector 1  (0x0200): FAT table (17 sectors)
    ///   Sector 18 (0x2400): Root directory (fixed, 16 entries)
    ///   Sector 19 (0x2600): Cluster 2 — SUBDIR contents
    ///   Sector 20 (0x2800): Cluster 3 — CHILD.TXT data
    ///   Sector 21 (0x2A00): Cluster 4 — ROOT_F.TXT data
    ///
    /// Root entries: SUBDIR (dir, cluster 2), ROOT_F (file, cluster 4)
    /// SUBDIR:       . (cluster 2), .. (cluster 0), CHILD (file, cluster 3)
    fn build_fat16_image() -> Vec<u8> {
        // Image needs data through cluster 4 = sector 21.
        let mut img = vec![0u8; 22 * 512];

        // --- Boot sector (sector 0) ---
        img[0x00..0x03].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[0x03..0x0B].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1; // sectors_per_cluster
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        img[0x10] = 1; // num_fats
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
        // 4104 total sectors → 4085 data clusters → FAT16
        img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes());
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes());
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        // FAT16 EBPB
        img[0x24] = 0x80;
        img[0x26] = 0x29;
        img[0x27..0x2B].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        img[0x2B..0x36].copy_from_slice(b"NO NAME    ");
        img[0x36..0x3E].copy_from_slice(b"FAT16   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // --- FAT table (sector 1, offset 0x200) ---
        let f = 0x200;
        img[f..f + 2].copy_from_slice(&0xFFF8u16.to_le_bytes()); // FAT[0]
        img[f + 2..f + 4].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[1]
        img[f + 4..f + 6].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[2] SUBDIR
        img[f + 6..f + 8].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[3] CHILD
        img[f + 8..f + 10].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[4] ROOT_F

        // --- Root directory (sector 18, offset 0x2400) ---
        let r = 18 * 512;
        write_dir_entry(&mut img, r, b"SUBDIR     ", 0x10, 2, 0);
        write_dir_entry(&mut img, r + 32, b"ROOT_F  TXT", 0x20, 4, 100);
        // entry at r+64 is all zeros → end-of-directory

        // --- Cluster 2 / SUBDIR (sector 19, offset 0x2600) ---
        let s = 19 * 512;
        write_dir_entry(&mut img, s, b".          ", 0x10, 2, 0);
        write_dir_entry(&mut img, s + 32, b"..         ", 0x10, 0, 0);
        write_dir_entry(&mut img, s + 64, b"CHILD   TXT", 0x20, 3, 50);
        // entry at s+96 is all zeros → end-of-directory

        img
    }

    /// Build a minimal FAT32 image.
    ///
    /// Layout (sector_size=512, 1 sector/cluster):
    ///   Sectors 0-31  : Reserved (boot at 0)
    ///   Sectors 32-543: FAT table (512 sectors)
    ///   Sector 544    : Cluster 2 — root directory
    ///   Sector 545    : Cluster 3 — SUBDIR contents
    ///   Sector 546    : Cluster 4 — NESTED.TXT data
    ///   Sector 547    : Cluster 5 — ROOT_F.TXT data
    ///
    /// Root (cluster 2): SUBDIR (dir, cluster 3), ROOT_F (file, cluster 5)
    /// SUBDIR (cluster 3): . (cluster 3), .. (cluster 0), NESTED (file, cluster 4)
    fn build_fat32_image() -> Vec<u8> {
        // Image needs data through cluster 5 = sector 547.
        let mut img = vec![0u8; 548 * 512];

        // --- Boot sector (sector 0) ---
        img[0x00..0x03].copy_from_slice(&[0xEB, 0x58, 0x90]);
        img[0x03..0x0B].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1; // sectors_per_cluster
        img[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes()); // reserved
        img[0x10] = 1; // num_fats
        // root_entry_count = 0 (FAT32 detection)
        // total_sectors_16 = 0 (FAT32 detection)
        img[0x15] = 0xF8;
        // sectors_per_fat_16 = 0 (FAT32 detection)
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        // total_sectors_32: 32 + 512 + 65525 = 66069
        img[0x20..0x24].copy_from_slice(&66069u32.to_le_bytes());
        // FAT32 EBPB
        img[0x24..0x28].copy_from_slice(&512u32.to_le_bytes()); // sectors_per_fat_32
        // ext_flags, fs_version: 0
        img[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root_cluster = 2
        img[0x30..0x32].copy_from_slice(&0xFFFFu16.to_le_bytes()); // no fsinfo
        // backup_boot_sector, reserved: 0
        img[0x40] = 0x80;
        img[0x42] = 0x29;
        img[0x43..0x47].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        img[0x47..0x52].copy_from_slice(b"NO NAME    ");
        img[0x52..0x5A].copy_from_slice(b"FAT32   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // --- FAT table (sector 32, offset 0x4000) ---
        let f = 32 * 512;
        img[f..f + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // FAT[0]
        img[f + 4..f + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[1]
        img[f + 8..f + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[2] root
        img[f + 12..f + 16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[3] SUBDIR
        img[f + 16..f + 20].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[4] NESTED
        img[f + 20..f + 24].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // FAT[5] ROOT_F

        // --- Cluster 2 / root dir (sector 544, offset 0x44000) ---
        let r = 544 * 512;
        write_dir_entry(&mut img, r, b"SUBDIR     ", 0x10, 3, 0);
        write_dir_entry(&mut img, r + 32, b"ROOT_F  TXT", 0x20, 5, 100);

        // --- Cluster 3 / SUBDIR (sector 545, offset 0x44200) ---
        let s = 545 * 512;
        write_dir_entry(&mut img, s, b".          ", 0x10, 3, 0);
        write_dir_entry(&mut img, s + 32, b"..         ", 0x10, 0, 0);
        write_dir_entry(&mut img, s + 64, b"NESTD   TXT", 0x20, 4, 50);

        img
    }

    /// Collect entry names from a walk_dir traversal.
    fn walk_names(cursor: &mut Cursor<Vec<u8>>, dir: &mut FatDirectory<'_>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut names = Vec::new();
        walk_dir(cursor, dir, &mut seen, &mut |e: FatDirectoryEntry<'_>| {
            names.push(e.inner().short_name_string());
        })
        .expect("walk_dir failed");
        names
    }

    // ---------------------------------------------------------------
    // Runtime traversal tests
    // ---------------------------------------------------------------

    /// The traversal iterator must skip `.` and `..` entries so that
    /// `walk_dir` never sees FAT navigation entries.
    #[test]
    fn dot_entries_filtered_from_traversal_iter() {
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // Iterate SUBDIR (cluster 2) which contains `.`, `..`, CHILD.TXT
        let file = FatFile::new(&fat, Some(2), true, 0);
        let mut dir = FatDirectory::new(file).expect("is directory");
        let mut iter = dir.entries(&mut cur).expect("entries");

        let mut names = Vec::new();
        while let Some(entry) = iter.try_next(&mut cur).expect("next") {
            names.push(entry.inner().short_name_string());
        }

        assert_eq!(names, vec!["CHILD.TXT"]);
    }

    /// Walking from a subdirectory must not escape to the parent via
    /// `..` entries — only descendants should be visited.
    #[test]
    fn walk_dir_stays_within_fat16_subtree() {
        let img = build_fat16_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // Walk from SUBDIR (cluster 2)
        let file = FatFile::new(&fat, Some(2), true, 0);
        let mut subdir = FatDirectory::new(file).expect("is directory");
        let names = walk_names(&mut cur, &mut subdir);

        assert_eq!(
            names,
            vec!["CHILD.TXT"],
            "walk_dir escaped subtree or yielded dot entries"
        );
    }

    /// Walking a FAT32 image from a subdirectory must not escape
    /// upward through `..` (which stores cluster 0 for root).
    #[test]
    fn walk_dir_stays_within_fat32_subtree() {
        let img = build_fat32_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // Walk from root — should see SUBDIR, NESTD.TXT, ROOT_F.TXT
        let mut root_dir = FatDirectory::new(fat.root_directory()).expect("is directory");
        let root_names = walk_names(&mut cur, &mut root_dir);
        assert_eq!(root_names, vec!["SUBDIR", "NESTD.TXT", "ROOT_F.TXT"],);

        // Walk from SUBDIR (cluster 3) — only NESTD.TXT
        let file = FatFile::new(&fat, Some(3), true, 0);
        let mut subdir = FatDirectory::new(file).expect("is directory");
        let subdir_names = walk_names(&mut cur, &mut subdir);
        assert_eq!(
            subdir_names,
            vec!["NESTD.TXT"],
            "walk_dir escaped FAT32 subtree via cluster-0 dotdot"
        );
    }

    /// On FAT32, an entry whose first_cluster is 0 (the conventional
    /// encoding for "parent is root") must produce the same `FsId` as
    /// the root directory itself so cycle detection works.
    #[test]
    fn fat32_entry_id_maps_cluster_zero_to_root() {
        let img = build_fat32_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        // The root directory's own id
        let root_dir = FatDirectory::new(fat.root_directory()).expect("is directory");
        let root_id = <FatDirectory<'_> as FsDirectory<Cursor<Vec<u8>>>>::id(&root_dir);

        // Construct a directory entry with cluster = 0
        let mut raw = [0u8; 32];
        raw[0..11].copy_from_slice(b"..         ");
        raw[0x0B] = 0x10; // DIRECTORY
        let data = DirFileEntryData::read_from_bytes(&raw).unwrap();
        let dir_entry = FatDirEntry::new(data);
        assert_eq!(dir_entry.first_cluster(), 0);

        let traversal_entry = FatDirectoryEntry {
            entry: dir_entry,
            fat: &fat,
        };
        let entry_id = <FatDirectoryEntry<'_> as FsDirEntry<Cursor<Vec<u8>>>>::id(&traversal_entry);

        assert_eq!(
            entry_id, root_id,
            "cluster-0 entry id ({entry_id:?}) must match root id ({root_id:?})"
        );
        assert_eq!(root_id, Some(FsId(2)), "FAT32 root cluster is 2");
    }

    /// Build a FAT16 image where the first root directory entry is valid
    /// ("GOOD.TXT") and the second entry has all-0xFF bytes, which is
    /// not a valid end marker (0x00) or deleted marker (0xE5) but will
    /// be parsed as an entry. The third entry is a valid file
    /// ("AFTER.TXT") followed by an end marker.
    ///
    /// If iteration silently stops on parse issues, "AFTER.TXT" will be
    /// missing from results. Correct behavior: yield "GOOD.TXT", then
    /// yield the corrupt entry (it parses as a short name entry with
    /// garbage attributes), then yield "AFTER.TXT".
    fn build_fat16_image_with_corrupt_entry() -> Vec<u8> {
        let mut img = build_fat16_image();

        // Root directory is at sector 18 (offset 0x2400).
        // Overwrite entry layout:
        //   [0] GOOD.TXT  — valid file entry
        //   [1] corrupt   — all 0xFF bytes (not a valid end/deleted marker)
        //   [2] AFTER.TXT — valid file entry
        //   [3] end marker (0x00)
        let r = 18 * 512;

        // Entry 0: GOOD.TXT
        // Clear first
        img[r..r + 32].fill(0);
        write_dir_entry(&mut img, r, b"GOOD    TXT", 0x20, 4, 100);

        // Entry 1: corrupt — all 0xFF
        // The first byte 0xFF is neither 0x00 (end) nor 0xE5 (deleted).
        // Attributes byte 0xFF does NOT match LFN (0x0F exact), so this
        // is treated as a short-name entry with garbage attributes.
        // FromBytes accepts any 32-byte pattern, so it parses without
        // error and is yielded as Some(Ok(...)).
        img[r + 32..r + 64].fill(0xFF);

        // Entry 2: AFTER.TXT
        img[r + 64..r + 96].fill(0);
        write_dir_entry(&mut img, r + 64, b"AFTER   TXT", 0x20, 4, 50);

        // Entry 3: end marker
        img[r + 96..r + 128].fill(0);

        img
    }

    /// Verify that garbage bytes (all-0xFF) in a directory entry are
    /// parsed as a short-name entry and do not stop iteration. Both
    /// the entry before and after the garbage are yielded.
    #[test]
    fn garbage_entry_parsed_and_iteration_continues() {
        let img = build_fat16_image_with_corrupt_entry();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let mut entries = fat.root_dir_entries();
        let mut names = Vec::new();
        let mut errors = Vec::new();

        loop {
            match entries.next(&mut cur) {
                Some(Ok(entry)) => names.push(entry.short_name_string()),
                Some(Err(e)) => {
                    errors.push(e);
                    // After an error, iteration is finished — this is
                    // correct because the caller must decide whether
                    // to continue with partial results.
                    break;
                }
                None => break,
            }
        }

        // GOOD.TXT must have been yielded before the corrupt entry.
        // The all-0xFF entry (attr=0xFF) does not match LFN (0x0F exact),
        // so it is yielded as a short-name entry with garbage fields.
        // AFTER.TXT follows and must also be yielded.
        assert!(
            names.contains(&String::from("GOOD.TXT")),
            "GOOD.TXT must be yielded: got {names:?}"
        );
        assert!(
            names.contains(&String::from("AFTER.TXT")),
            "AFTER.TXT must be yielded after corrupt entry: got {names:?}"
        );
    }

    /// A fixed-region root with no end marker exhausts normally once
    /// all allocated entries are consumed (no error expected).
    #[test]
    fn no_end_marker_in_fixed_root_exhausts_normally() {
        let mut img = build_fat16_image();

        // Fill the entire root directory region with non-zero
        // non-deleted bytes that parse as short-name entries, then
        // remove the end marker. The FAT16 root has 16 entries
        // (16 * 32 = 512 bytes at offset 0x2400).
        let r = 18 * 512;
        for i in 0..16 {
            let off = r + i * 32;
            img[off..off + 32].fill(0);
            // Valid-looking short name entry with ARCHIVE attribute
            write_dir_entry(&mut img, off, b"FILE       ", 0x20, 0, 0);
        }

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let mut entries = fat.root_dir_entries();

        // The fixed root has exactly 16 entries. Once all are
        // consumed, the iterator returns None (fixed region
        // exhausted). This is correct — no corruption, just no
        // end marker within the allocated region.
        let mut count = 0;
        let mut saw_error = false;
        loop {
            match entries.next(&mut cur) {
                Some(Ok(_)) => count += 1,
                Some(Err(_)) => {
                    saw_error = true;
                    break;
                }
                None => break,
            }
        }

        // All 16 entries should have been yielded (they look valid).
        assert_eq!(count, 16, "all 16 root entries should be parsed");
        assert!(
            !saw_error,
            "no error expected — fixed root exhausts normally"
        );
    }

    /// Verify that `MalformedDirEntry` includes the correct byte offset
    /// when reporting corruption.
    #[test]
    fn malformed_dir_entry_includes_byte_offset() {
        let err = FatError::MalformedDirEntry {
            byte_offset: 0x2420,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("0x2420"),
            "error message should include offset: {msg}"
        );
        assert_eq!(fs_common::error::FsError::byte_offset(&err), Some(0x2420));
    }

    /// Verify that corrupted entries in a cluster-chain directory
    /// (FAT32 root) do not silently stop iteration.
    #[test]
    fn corrupt_entry_in_fat32_cluster_chain() {
        let mut img = build_fat32_image();

        // FAT32 root is at cluster 2 = sector 544 (offset 0x44000).
        // Overwrite to: [0] VALID.TXT, [1] all-0xFF garbage, [2] AFTER.TXT, [3] end
        let r = 544 * 512;

        img[r..r + 32].fill(0);
        write_dir_entry(&mut img, r, b"VALID   TXT", 0x20, 5, 100);

        // Corrupt entry — all 0xFF, parsed as short-name (attr 0xFF != LFN 0x0F)
        img[r + 32..r + 64].fill(0xFF);

        img[r + 64..r + 96].fill(0);
        write_dir_entry(&mut img, r + 64, b"AFTER   TXT", 0x20, 5, 50);

        img[r + 96..r + 128].fill(0);

        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let mut entries = fat.root_dir_entries();
        let mut names = Vec::new();

        loop {
            match entries.next(&mut cur) {
                Some(Ok(entry)) => names.push(entry.short_name_string()),
                Some(Err(_)) => break,
                None => break,
            }
        }

        assert!(
            names.contains(&String::from("VALID.TXT")),
            "VALID.TXT must be yielded: got {names:?}"
        );
        assert!(
            names.contains(&String::from("AFTER.TXT")),
            "AFTER.TXT must be yielded after corrupt entry: got {names:?}"
        );
    }
}
