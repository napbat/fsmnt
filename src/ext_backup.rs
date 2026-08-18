//! Finding an ext filesystem's group-1 backup superblock when nothing is
//! readable at the offset the caller asked for.
//!
//! "No filesystem here" has two very different causes: the offset is
//! wrong, or the offset is right and the metadata at it is destroyed. A
//! wiped or overwritten first block is common — a partial re-partition, a
//! bad sector at LBA 0, a `dd` that started late — and it costs nothing to
//! tell the two apart, because ext leaves a copy of the superblock one
//! block group in. If a copy that names group 1 sits exactly where this
//! offset's geometry says it should, the offset was right after all and
//! the volume is openable from the copy.

use fsmnt_device::{
    DetectedBootSector, FilesystemOpenOptions, ImageReader, ext_backup_superblock_info_at,
};

/// Classify a source the caller has asked to open from a backup metadata
/// copy.
///
/// Boot-sector detection reads the primary superblock, which in this case
/// is the very thing that is unreadable — so it reports `Unknown` and no
/// driver would be consulted at all. Asking for a backup superblock *is*
/// the assertion that this is an ext volume, so the request itself selects
/// the driver; the copy is then validated when the driver reads it, and an
/// offset that holds no such copy still fails there.
pub(crate) fn detection_with_backup_request(
    detected: DetectedBootSector,
    filesystem: &FilesystemOpenOptions,
) -> DetectedBootSector {
    if detected == DetectedBootSector::Unknown && filesystem.ext_backup_superblock().is_some() {
        DetectedBootSector::Ext
    } else {
        detected
    }
}

/// Distance in bytes from the start of a filesystem to block group 1, for
/// each block size a default `mke2fs` run produces.
///
/// One block bitmap covers `8 × block_size` blocks, and mkfs sizes a block
/// group to exactly that, so group 1 begins at `(first_data_block +
/// 8 × block_size) × block_size` — 1 KiB blocks keep block 0 for the boot
/// area and so land 1024 bytes later than the round figure.
const GROUP_ONE_DISTANCES: [u64; 3] = [
    (1 + 8192) * 1024, // 1 KiB blocks: 8 389 632
    16_384 * 2048,     // 2 KiB blocks: 33 554 432
    32_768 * 4096,     // 4 KiB blocks: 134 217 728
];

/// Block sizes ext supports.
const BLOCK_SIZES: [u64; 7] = [1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Bytes a probe sits before the copy it is looking for.
///
/// A filesystem start keeps its superblock 1024 bytes in, so the shared
/// probe helpers expect that layout; a backup copy instead begins at byte
/// zero of its block group. Probing 1024 bytes early lines the two up.
const SUPERBLOCK_PREFIX: u64 = 1024;

/// Every distance at which block group 1 could begin, the mkfs defaults
/// first.
///
/// [`GROUP_ONE_DISTANCES`] is what a stock image matches, and trying those
/// three first means the common case costs three reads. `mke2fs -g` can
/// also shrink a block group below one bitmap block's worth of blocks,
/// which moves group 1 nearer the start, so the halved sizes follow. Every
/// hit is confirmed against the geometry the copy itself records, so the
/// wider search cannot produce a wrong answer — only a few more reads on a
/// path that has already failed.
fn group_one_distances(limit: u64) -> Vec<u64> {
    let mut extras = Vec::new();
    for block_size in BLOCK_SIZES {
        let first_data_block = u64::from(block_size == 1024);
        let mut blocks_per_group = block_size * 8;
        while blocks_per_group >= 8 {
            extras.push((blocks_per_group + first_data_block) * block_size);
            blocks_per_group /= 2;
        }
    }
    extras.sort_unstable();

    let mut distances: Vec<u64> = Vec::with_capacity(extras.len());
    for distance in GROUP_ONE_DISTANCES.into_iter().chain(extras) {
        if distance > SUPERBLOCK_PREFIX && distance < limit && !distances.contains(&distance) {
            distances.push(distance);
        }
    }
    distances
}

/// Look for the backup superblock of a filesystem whose primary metadata
/// at `offset` is unreadable.
///
/// Returns the byte offset of group 1's copy — the first block of that
/// group, which is where `--backup-superblock 1` reads from. `size_bytes`
/// bounds the search to the selected media range.
///
/// A candidate counts only when it names group 1 *and* the geometry it
/// records places the start of its filesystem back at `offset`, so a
/// backup belonging to some other volume elsewhere on the media cannot be
/// mistaken for this one's.
///
/// # Errors
///
/// Returns an error when a seek or read on the image fails.
pub(crate) fn find_group_one_backup(
    image: &mut ImageReader,
    offset: u64,
    size_bytes: u64,
) -> std::io::Result<Option<u64>> {
    for distance in group_one_distances(size_bytes) {
        let Some(probe_offset) = offset
            .checked_add(distance)
            .and_then(|start| start.checked_sub(SUPERBLOCK_PREFIX))
        else {
            continue;
        };
        let Some(info) = ext_backup_superblock_info_at(image, probe_offset)? else {
            continue;
        };
        if info.group == 1 && info.filesystem_start(probe_offset) == Some(offset) {
            return Ok(Some(offset + distance));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_layouts_are_probed() {
        let distances = group_one_distances(u64::MAX);
        for expected in GROUP_ONE_DISTANCES {
            assert!(
                distances.contains(&expected),
                "default group-1 distance {expected} must be probed",
            );
        }
        assert_eq!(GROUP_ONE_DISTANCES, [8_389_632, 33_554_432, 134_217_728]);
    }

    #[test]
    fn a_smaller_group_size_is_probed_too() {
        // `mkfs.ext4 -b 1024 -g 1024` puts group 1 at block 1025.
        assert!(group_one_distances(u64::MAX).contains(&(1025 * 1024)));
    }

    #[test]
    fn distances_stay_inside_the_selected_range() {
        assert!(
            group_one_distances(2_000_000)
                .iter()
                .all(|distance| *distance < 2_000_000)
        );
    }
}
