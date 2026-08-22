//! Synthetic FAT volume builders for cross-crate integration tests.

/// Path of the regular file in [`three_cluster_fat16_image`].
pub const THREE_CLUSTER_FILE_PATH: &str = "/FILE.BIN";

/// Build a FAT16 image containing one 1,200-byte file across three clusters.
///
/// The returned tuple contains the volume bytes followed by the exact file
/// payload. Clusters 2, 3, and 4 form one chain, while their adjacent FAT
/// entries share a 512-byte table sector so cache behavior is deterministic.
#[must_use]
pub fn three_cluster_fat16_image() -> (Vec<u8>, Vec<u8>) {
    const SECTOR_SIZE: usize = 512;
    const TOTAL_SECTORS: usize = 4_104;
    const SECTORS_PER_FAT: usize = 17;
    const ROOT_DIRECTORY_SECTOR: usize = 1 + SECTORS_PER_FAT;
    const FIRST_DATA_SECTOR: usize = ROOT_DIRECTORY_SECTOR + 1;
    const FILE_SIZE: usize = 1_200;

    let mut image = vec![0_u8; TOTAL_SECTORS * SECTOR_SIZE];
    image[0..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    image[3..11].copy_from_slice(b"MSDOS5.0");
    image[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    image[0x0d] = 1;
    image[0x0e..0x10].copy_from_slice(&1_u16.to_le_bytes());
    image[0x10] = 1;
    image[0x11..0x13].copy_from_slice(&16_u16.to_le_bytes());
    image[0x13..0x15].copy_from_slice(&4_104_u16.to_le_bytes());
    image[0x15] = 0xf8;
    image[0x16..0x18].copy_from_slice(&17_u16.to_le_bytes());
    image[0x24] = 0x80;
    image[0x26] = 0x29;
    image[0x36..0x3e].copy_from_slice(b"FAT16   ");
    image[0x1fe] = 0x55;
    image[0x1ff] = 0xaa;

    let table = SECTOR_SIZE;
    image[table..table + 2].copy_from_slice(&0xfff8_u16.to_le_bytes());
    image[table + 2..table + 4].copy_from_slice(&0xffff_u16.to_le_bytes());
    image[table + 4..table + 6].copy_from_slice(&3_u16.to_le_bytes());
    image[table + 6..table + 8].copy_from_slice(&4_u16.to_le_bytes());
    image[table + 8..table + 10].copy_from_slice(&0xffff_u16.to_le_bytes());

    let root = ROOT_DIRECTORY_SECTOR * SECTOR_SIZE;
    image[root..root + 11].copy_from_slice(b"FILE    BIN");
    image[root + 0x0b] = 0x20;
    image[root + 0x1a..root + 0x1c].copy_from_slice(&2_u16.to_le_bytes());
    image[root + 0x1c..root + 0x20].copy_from_slice(&1_200_u32.to_le_bytes());

    let mut payload = Vec::with_capacity(FILE_SIZE);
    payload.extend((0_u8..=250).cycle().take(FILE_SIZE));

    let data = FIRST_DATA_SECTOR * SECTOR_SIZE;
    image[data..data + SECTOR_SIZE].copy_from_slice(&payload[..SECTOR_SIZE]);
    image[data + SECTOR_SIZE..data + 2 * SECTOR_SIZE]
        .copy_from_slice(&payload[SECTOR_SIZE..2 * SECTOR_SIZE]);
    image[data + 2 * SECTOR_SIZE..data + 2 * SECTOR_SIZE + 176]
        .copy_from_slice(&payload[2 * SECTOR_SIZE..]);

    (image, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_contains_the_declared_payload() {
        let (image, payload) = three_cluster_fat16_image();
        assert_eq!(payload.len(), 1_200);
        assert_eq!(&image[0x1fe..0x200], [0x55, 0xaa]);
        assert_eq!(&image[19 * 512..19 * 512 + 512], &payload[..512]);
    }
}
