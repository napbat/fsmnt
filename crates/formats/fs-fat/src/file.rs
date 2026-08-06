use crate::dir_entry::FatDirEntries;
use crate::error::{FatError, Result};
use crate::fat::Fat;
use crate::value::FatFileValue;

/// A file or directory in a FAT filesystem.
#[derive(Clone, Debug)]
pub struct FatFile<'n> {
    fat: &'n Fat,
    /// First cluster of the file/directory, or `None` for FAT12/16 root directory.
    first_cluster: Option<u32>,
    /// Whether this is a directory.
    is_directory: bool,
    /// Size of the file in bytes (0 for directories).
    file_size: u32,
}

impl<'n> FatFile<'n> {
    /// Creates a new `FatFile` with the given parameters.
    pub(crate) fn new(
        fat: &'n Fat,
        first_cluster: Option<u32>,
        is_directory: bool,
        file_size: u32,
    ) -> Self {
        Self {
            fat,
            first_cluster,
            is_directory,
            file_size,
        }
    }

    /// Returns `true` if this is a directory.
    #[inline]
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Returns the size of the file in bytes.
    ///
    /// For directories, this returns 0.
    #[inline]
    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    /// Returns the first cluster of this file/directory, if any.
    ///
    /// Returns `None` for FAT12/16 root directory (which is at a fixed location).
    #[inline]
    pub fn first_cluster(&self) -> Option<u32> {
        self.first_cluster
    }

    /// Returns an iterator over the entries in this directory.
    ///
    /// # Errors
    ///
    /// Returns an error if this is not a directory.
    pub fn dir_entries(&self) -> Result<FatDirEntries<'n>> {
        if !self.is_directory {
            return Err(FatError::NotADirectory);
        }

        match self.first_cluster {
            Some(cluster) => {
                // Subdirectory or FAT32 root: use cluster chain
                Ok(FatDirEntries::new_cluster_chain(self.fat, cluster))
            }
            None => {
                // FAT12/16 root directory: use fixed location
                Ok(FatDirEntries::new_fixed(
                    self.fat,
                    self.fat.root_dir_offset(),
                    self.fat.root_dir_size(),
                ))
            }
        }
    }

    /// Returns a value reader for the file's data.
    ///
    /// The returned [`FatFileValue`] can be used to read the file's contents
    /// by following its cluster chain.
    ///
    /// # Errors
    ///
    /// Returns an error if this is a directory.
    pub fn data(&self) -> Result<FatFileValue<'n>> {
        if self.is_directory {
            return Err(FatError::IsADirectory);
        }

        Ok(FatFileValue::new(
            self.fat,
            self.first_cluster,
            self.file_size as u64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::Fat;
    use fs_common::boot_sector::BOOT_SIGNATURE;
    use std::io::Cursor;

    /// Minimal in-memory FAT16 image — just enough for `Fat::new` to succeed.
    /// Layout: bps=512, spc=1, reserved=1, fats=1, root_entries=16, spf16=1,
    /// total_sectors=20 → first_data_sector = 1+1+1 = 3, data_sectors = 17,
    /// cluster_count = 17 < 4085 → FAT12.
    fn minimal_fat_image() -> Vec<u8> {
        let mut img = vec![0u8; 20 * 512];
        img[0x00..0x03].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[0x03..0x0B].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1; // spc
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved
        img[0x10] = 1; // num_fats
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes()); // root_entries
        img[0x13..0x15].copy_from_slice(&20u16.to_le_bytes()); // total_sectors_16
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // spf16
        img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        img[0x24] = 0x80;
        img[0x26] = 0x29;
        img[0x36..0x3E].copy_from_slice(b"FAT12   ");
        img[0x1FE..0x200].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
        img
    }

    #[test]
    fn is_directory_reflects_constructor_arg() {
        // Catches `is_directory -> bool with true`: the file variant must
        // return false, and the directory variant must return true.
        let img = minimal_fat_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let file = FatFile::new(&fat, Some(2), false, 100);
        assert!(!file.is_directory());

        let dir = FatFile::new(&fat, Some(2), true, 0);
        assert!(dir.is_directory());
    }

    #[test]
    fn file_size_returns_constructor_arg() {
        // Catches `file_size -> u32 with 0` and `-> 1`: build files with
        // distinct sizes and assert each. The non-zero, non-one values
        // make both constant-replacement mutants visible.
        let img = minimal_fat_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let small = FatFile::new(&fat, Some(2), false, 7);
        assert_eq!(small.file_size(), 7);

        let medium = FatFile::new(&fat, Some(2), false, 12345);
        assert_eq!(medium.file_size(), 12345);

        // Boundary: zero is a valid file size and must round-trip.
        let empty = FatFile::new(&fat, Some(2), false, 0);
        assert_eq!(empty.file_size(), 0);
    }

    #[test]
    fn first_cluster_round_trips() {
        let img = minimal_fat_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let file = FatFile::new(&fat, Some(42), false, 0);
        assert_eq!(file.first_cluster(), Some(42));

        let no_cluster = FatFile::new(&fat, None, true, 0);
        assert_eq!(no_cluster.first_cluster(), None);
    }

    #[test]
    fn data_on_directory_returns_is_a_directory_error() {
        let img = minimal_fat_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let dir = FatFile::new(&fat, Some(2), true, 0);
        let err = dir.data().unwrap_err();
        assert!(matches!(err, FatError::IsADirectory));
    }

    #[test]
    fn dir_entries_on_file_returns_not_a_directory_error() {
        let img = minimal_fat_image();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");

        let file = FatFile::new(&fat, Some(2), false, 100);
        let err = file.dir_entries().unwrap_err();
        assert!(matches!(err, FatError::NotADirectory));
    }
}
