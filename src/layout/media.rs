//! Enumeration shared by every medium: images and physical drives alike.
//!
//! Everything here works on a [`Disk`] over any `Read + Seek` source, or on
//! the hits of a scan, so [`image_layout`](super::image_layout) and
//! [`drive_layout`](super::drive_layout) cannot drift apart in what they
//! call partition 0.
//!
//! A medium's length is an `Option<u64>` throughout: an image always knows
//! how long it is, whereas a drive whose size the operating system declined
//! to report does not. `None` means "unbounded as far as anyone here can
//! tell", which is why such a medium never reports missing bytes and gives
//! its whole-medium entry a size of 0.

use std::io::{Read, Seek};

use fsmnt_device::{DetectedBootSector, Disk, DiskLayout};

use super::{LayoutKind, LayoutOrigin, LayoutPartition};
use crate::{ScanHit, ScanHitKind};

/// What one pass over a medium's partition table found.
pub(crate) struct MediaEntries {
    /// Where the entries were read from.
    pub(crate) origin: LayoutOrigin,
    /// The table kind, mirroring the disk layout.
    pub(crate) kind: LayoutKind,
    /// The mountable extents, in ordinal order.
    pub(crate) partitions: Vec<LayoutPartition>,
}

/// Enumerate the partitions an already-opened [`Disk`] describes.
///
/// `size_bytes` is the length of the medium behind the disk, or `None` when
/// that is unknown; it decides how much of each extent is reported missing
/// and bounds filesystem detection to bytes that exist.
pub(crate) fn media_layout<R: Read + Seek>(
    disk: &mut Disk<R>,
    size_bytes: Option<u64>,
) -> MediaEntries {
    let origin = match disk.layout() {
        DiskLayout::Gpt {
            from_backup: true, ..
        } => LayoutOrigin::BackupTable,
        DiskLayout::Gpt { .. } | DiskLayout::Mbr { .. } => LayoutOrigin::Table,
        DiskLayout::Bare(_) | DiskLayout::Unknown => LayoutOrigin::None,
    };
    let (kind, entries) = match disk.layout().clone() {
        DiskLayout::Gpt { .. } => (LayoutKind::Gpt, gpt_entries(disk)),
        DiskLayout::Mbr { .. } => (LayoutKind::Mbr, mbr_entries(disk)),
        DiskLayout::Bare(detected) => (
            LayoutKind::Bare(detected),
            vec![whole_media_entry(size_bytes)],
        ),
        DiskLayout::Unknown => (LayoutKind::Unknown, vec![whole_media_entry(size_bytes)]),
    };

    let partitions = entries
        .into_iter()
        .enumerate()
        .map(|(ordinal, entry)| LayoutPartition {
            ordinal,
            offset: entry.offset,
            size_bytes: entry.size_bytes,
            missing_bytes: missing_bytes(entry.offset, entry.size_bytes, size_bytes),
            type_name: entry.type_name,
            name: entry.name,
            detected: detect_at(disk, entry.offset, size_bytes),
        })
        .collect();

    MediaEntries {
        origin,
        kind,
        partitions,
    }
}

/// Turn the hits of a media scan into a synthetic partition list.
///
/// Every mountable hit (see [`crate::mountable_hits`]) becomes one entry, in
/// scan order: its offset is the filesystem start, its size is what the
/// filesystem claims for itself (or the rest of the medium when the format
/// does not say), its type is the detected filesystem, and it has no name.
/// An ext filesystem found only through a backup superblock is listed too —
/// at the start the copy implies — so selecting it produces the "primary
/// damaged, retry with `--backup-superblock`" guidance rather than nothing.
pub(crate) fn layout_from_hits(hits: &[ScanHit], size_bytes: Option<u64>) -> Vec<LayoutPartition> {
    crate::mountable_hits(hits)
        .into_iter()
        .enumerate()
        .map(|(ordinal, hit)| {
            let offset = hit.mount_offset().unwrap_or(hit.offset);
            // 0 for a medium of unknown length carries the same meaning it
            // does for a whole-medium entry: runs to the end, extent unknown.
            let rest = size_bytes.map_or(0, |size| size.saturating_sub(offset));
            let claimed = hit.size_bytes.unwrap_or(rest);
            let (type_name, detected) = match hit.kind {
                ScanHitKind::Filesystem(detected) => {
                    (Some(format!("{detected:?} (scan)")), Some(detected))
                }
                ScanHitKind::ExtBackupSuperblock { group, .. } => (
                    Some(format!(
                        "Ext (scan; primary damaged, backup at group {group})"
                    )),
                    Some(DetectedBootSector::Unknown),
                ),
                ScanHitKind::PartitionTable(_) => (None, None),
            };
            LayoutPartition {
                ordinal,
                offset,
                size_bytes: claimed,
                missing_bytes: missing_bytes(offset, claimed, size_bytes),
                type_name,
                name: None,
                detected,
            }
        })
        .collect()
}

/// How much of the extent `offset..offset + size_bytes` the medium lacks.
///
/// A medium whose own length is unknown lacks nothing that can be proved,
/// so it always answers 0.
pub(crate) fn missing_bytes(offset: u64, size_bytes: u64, media_size: Option<u64>) -> u64 {
    let Some(media_size) = media_size else {
        return 0;
    };
    offset
        .saturating_add(size_bytes)
        .saturating_sub(media_size)
        .min(size_bytes)
}

/// Classify the boot sector at `offset` within a medium of `size_bytes`.
///
/// A partition table can describe partitions the medium does not carry — a
/// partition-table-only dump, or a truncated acquisition. Reads past the end
/// of the medium come back empty and would classify as `Unknown`, so those
/// partitions report `None` ("not present") instead.
fn detect_at<R: Read + Seek>(
    disk: &mut Disk<R>,
    offset: u64,
    size_bytes: Option<u64>,
) -> Option<DetectedBootSector> {
    if size_bytes.is_some_and(|size| offset >= size) {
        return None;
    }
    disk.detect_boot_sector_at(offset).ok()
}

/// A partition extent before filesystem detection has been attempted.
struct RawEntry {
    /// Byte offset of the extent within the medium.
    offset: u64,
    /// Length of the extent in bytes.
    size_bytes: u64,
    /// Partition type as named by the partition table.
    type_name: Option<String>,
    /// Partition label, where the table stores one.
    name: Option<String>,
}

/// The single extent used for media with no partition table.
///
/// A medium of unknown length gets size 0, which every consumer reads as
/// "to the end of the medium".
fn whole_media_entry(size_bytes: Option<u64>) -> RawEntry {
    RawEntry {
        offset: 0,
        size_bytes: size_bytes.unwrap_or(0),
        type_name: None,
        name: None,
    }
}

/// Collect the non-empty GPT entries, skipping ones that cannot be read.
fn gpt_entries<R: Read + Seek>(disk: &mut Disk<R>) -> Vec<RawEntry> {
    let sector_size = disk.sector_size();
    let count = disk.partition_count();
    let mut entries = Vec::new();
    for index in 0..count {
        let Ok(entry) = disk.gpt_partition(index) else {
            continue;
        };
        if entry.is_empty() {
            continue;
        }
        let name = entry.name_string();
        entries.push(RawEntry {
            offset: entry.start_offset(sector_size),
            size_bytes: entry.size_bytes(sector_size),
            type_name: entry.type_name().map(str::to_string),
            name: (!name.is_empty()).then_some(name),
        });
    }
    entries
}

/// Collect the primary MBR entries in on-disk order.
fn mbr_entries<R: Read + Seek>(disk: &Disk<R>) -> Vec<RawEntry> {
    let sector_size = disk.sector_size();
    disk.mbr_partitions()
        .map(|entry| RawEntry {
            offset: entry.start_offset(sector_size),
            size_bytes: entry.size_bytes(sector_size),
            type_name: Some(
                entry
                    .type_name()
                    .map_or_else(|| format!("0x{:02X}", entry.partition_type), str::to_string),
            ),
            name: None,
        })
        .collect()
}
