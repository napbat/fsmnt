//! Shared test helpers for building minimal exFAT images.
//!
//! Used by tests in `exfat`, `fat`, `dir_iter`, and `file` modules.

use alloc::vec;
use alloc::vec::Vec;

use crate::boot_sector::compute_boot_checksum;
use crate::exfat::ExFat;

pub const BPS: usize = 512;
pub const TOTAL_SECTORS: usize = 103;

/// Writes a valid exFAT boot sector into `buf` at the given byte
/// offset.
pub fn write_boot_sector(buf: &mut [u8], base: usize) {
    let total_sectors = u64::try_from(TOTAL_SECTORS).expect("test sector count fits u64");
    buf[base] = 0xEB;
    buf[base + 1] = 0x76;
    buf[base + 2] = 0x90;
    buf[base + 3..base + 11].copy_from_slice(b"EXFAT   ");
    buf[base + 0x40..base + 0x48].copy_from_slice(&0u64.to_le_bytes());
    buf[base + 0x48..base + 0x50].copy_from_slice(&total_sectors.to_le_bytes());
    buf[base + 0x50..base + 0x54].copy_from_slice(&1u32.to_le_bytes());
    buf[base + 0x54..base + 0x58].copy_from_slice(&1u32.to_le_bytes());
    buf[base + 0x58..base + 0x5C].copy_from_slice(&3u32.to_le_bytes());
    buf[base + 0x5C..base + 0x60].copy_from_slice(&100u32.to_le_bytes());
    buf[base + 0x60..base + 0x64].copy_from_slice(&2u32.to_le_bytes());
    buf[base + 0x64..base + 0x68].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    buf[base + 0x68..base + 0x6A].copy_from_slice(&0x0100u16.to_le_bytes());
    buf[base + 0x6A..base + 0x6C].copy_from_slice(&0u16.to_le_bytes());
    buf[base + 0x6C] = 9;
    buf[base + 0x6D] = 0;
    buf[base + 0x6E] = 1;
    buf[base + 0x6F] = 0x80;
    buf[base + 0x70] = 50;
    buf[base + 0x1FE..base + 0x200].copy_from_slice(&0xAA55u16.to_le_bytes());
}

/// Builds a minimal valid exFAT image (103 sectors, 512 bytes each)
/// with a correct VBR checksum.
pub fn make_image() -> Vec<u8> {
    let mut image = vec![0u8; TOTAL_SECTORS * BPS];
    write_boot_sector(&mut image, 0);

    let checksum = compute_boot_checksum(&image[..BPS * 11], BPS);
    let cs_bytes = checksum.to_le_bytes();
    for i in 0..(BPS / 4) {
        let off = BPS * 11 + i * 4;
        image[off..off + 4].copy_from_slice(&cs_bytes);
    }
    image
}

/// Writes a u32 FAT entry for the given cluster.
pub fn set_fat_entry(image: &mut [u8], cluster: u32, value: u32) {
    let cluster = usize::try_from(cluster).expect("test cluster fits usize");
    let off = BPS + cluster * 4;
    image[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Returns the byte offset of the given cluster in the image.
pub fn cluster_heap_offset(cluster: u32) -> usize {
    let cluster = usize::try_from(cluster).expect("test cluster fits usize");
    3 * BPS + (cluster - 2) * BPS
}

/// Creates an `ExFat` from the given image and returns both.
pub fn make_exfat(image: Vec<u8>) -> (ExFat, std::io::Cursor<Vec<u8>>) {
    let mut cursor = std::io::Cursor::new(image);
    let exfat = ExFat::new(&mut cursor).unwrap();
    (exfat, cursor)
}
