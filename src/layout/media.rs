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
            ordinal: Some(ordinal),
            offset: entry.offset,
            size_bytes: entry.size_bytes,
            missing_bytes: missing_bytes(entry.offset, entry.size_bytes, size_bytes),
            type_name: entry.type_name,
            name: entry.name,
            detected: detect_at(disk, entry.offset, size_bytes),
            // A partition table describes bytes the medium carries; a
            // volume that began before the medium has no entry in one.
            head_absent: None,
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
/// So is a start whose superblock survived but whose group descriptor table
/// no longer verifies, once a backup superblock names that offset as its
/// filesystem's start; without that corroboration the copies are not
/// mountable and never reach this list.
///
/// One kind of entry is listed without being selectable: a filesystem whose
/// backups place its start *before* the medium
/// ([`ScanHit::head_absent`](crate::ScanHit::head_absent)). It is worth
/// seeing — it is often the largest thing on a salvaged slice — but there is
/// no extent on this medium to hand `--partition`, so it carries no ordinal
/// and its type text names the `--offset -N` command that does open it. The
/// alternative, letting `--scan --partition K` resolve to it, would have to
/// mean "partition 0 is the volume this medium is a piece of", which is not
/// a partition of this medium at all.
pub(crate) fn layout_from_hits(hits: &[ScanHit], size_bytes: Option<u64>) -> Vec<LayoutPartition> {
    let mut ordinals = 0_usize;
    hits.iter()
        .filter(|hit| hit.mount_offset().is_some() || hit.head_absent().is_some())
        .map(|hit| {
            let head_absent = hit.head_absent();
            // A volume that began before the medium is listed at the start
            // of the *volume*, which is where its own geometry counts from.
            let offset = if head_absent.is_some() {
                0
            } else {
                hit.mount_offset().unwrap_or(hit.offset)
            };
            // 0 for a medium of unknown length carries the same meaning it
            // does for a whole-medium entry: runs to the end, extent unknown.
            let rest = size_bytes.map_or(0, |size| size.saturating_sub(offset));
            let claimed = hit.size_bytes.unwrap_or(rest);
            let (type_name, detected) = scanned_type(hit, head_absent);
            let ordinal = head_absent.is_none().then(|| {
                let ordinal = ordinals;
                ordinals += 1;
                ordinal
            });
            LayoutPartition {
                ordinal,
                offset,
                size_bytes: claimed,
                missing_bytes: missing_bytes(offset, claimed, size_bytes),
                type_name,
                name: None,
                detected,
                head_absent,
            }
        })
        .collect()
}

/// The `TYPE` text and detected filesystem for one scanned entry.
fn scanned_type(
    hit: &ScanHit,
    head_absent: Option<u64>,
) -> (Option<String>, Option<DetectedBootSector>) {
    if let Some(before) = head_absent {
        let group = hit.backup_superblock_group().unwrap_or(1);
        return (
            Some(format!(
                "Ext (scan; begins {before} bytes into the filesystem — mount with --offset \
                 -{before} --backup-superblock {group})"
            )),
            Some(DetectedBootSector::Ext),
        );
    }
    match hit.kind {
        ScanHitKind::Filesystem(detected) => (Some(format!("{detected:?} (scan)")), Some(detected)),
        ScanHitKind::ExtBackupSuperblock { group, .. } => (
            Some(format!(
                "Ext (scan; primary damaged, backup at group {group})"
            )),
            Some(DetectedBootSector::Unknown),
        ),
        ScanHitKind::ExtPrimaryCopies { .. } => (
            Some(format!(
                "Ext (scan; descriptor table damaged, backup at group {})",
                hit.backup_superblocks
                    .first()
                    .map_or(0, |backup| backup.group)
            )),
            Some(DetectedBootSector::Ext),
        ),
        ScanHitKind::PartitionTable(_) => (None, None),
    }
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
