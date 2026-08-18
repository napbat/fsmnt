//! Read-only enumeration of what a medium contains.
//!
//! [`image_layout`] answers "what is inside this file?" and [`drive_layout`]
//! answers the same question for a physical drive, without opening a
//! filesystem: the partition table (if any) and every addressable partition
//! with its ordinal, byte offset, size, type, label, detected filesystem,
//! and how much of it the medium is missing.
//!
//! Both call the same enumeration over a [`Disk`](fsmnt_device::Disk), so an
//! image acquired from a drive and the drive itself cannot report different
//! ordinals for the same table.
//!
//! The ordinals reported here are the ones
//! [`ImageOpenOptions::with_partition`](crate::ImageOpenOptions::with_partition)
//! and `--partition` consume — all of them come from this enumeration, so a
//! partition listed here can be mounted by its number.
//!
//! Partition tables are written in the medium's logical sectors, so a dump
//! of a 4Kn drive puts its GPT header at byte 4096 and means every LBA in
//! the entry array counts 4096-byte units.
//! [`ImageLayoutOptions::with_sector_size`] and
//! [`DriveLayoutOptions::with_sector_size`] state the sector size; without
//! one, an image falls back to 4 KiB sectors when 512-byte sectors find no
//! table and a drive uses the size the operating system reports for it.

mod drive;
mod image;
mod media;

pub use drive::{DriveLayout, DriveLayoutError, DriveLayoutOptions, drive_layout};
pub(crate) use drive::{drive_length, scanned_extent};
pub use image::{
    ImageLayout, ImageLayoutOptions, image_layout, image_layout_with_options,
    image_layout_with_sector_size,
};
pub(crate) use image::{LocatedImagePartition, locate_image_partition};

use fsmnt_device::DetectedBootSector;

/// Logical sector size assumed for a medium with no better information: the
/// 512-byte sector every 512n and 512e drive reports.
pub(crate) const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Logical sector size tried when 512-byte sectors find no partition table.
///
/// 4Kn drives are the only common media whose table needs a different unit,
/// and a raw dump of one carries no geometry metadata to read it from.
const NATIVE_4K_SECTOR_SIZE: u32 = 4096;

/// Partition table (or lack of one) found at the start of a medium.
///
/// Mirrors [`DiskLayout`](fsmnt_device::DiskLayout) one variant for one
/// variant, so matching on it is exhaustive for as long as that type's is.
#[derive(Clone, Debug)]
pub enum LayoutKind {
    /// A GUID partition table; partitions come from its entry array.
    Gpt,
    /// A master boot record; partitions come from its primary entries.
    Mbr,
    /// No partition table — the whole medium is one filesystem of this type.
    Bare(DetectedBootSector),
    /// Neither a partition table nor a recognized filesystem at offset 0.
    Unknown,
    /// **Synthetic**: no table was read; the entries were reconstructed by
    /// scanning the medium for filesystem starts (see [`LayoutOrigin::Scan`]).
    Scanned,
}

/// Where a layout's entries came from — the provenance a listing or a mount
/// must state, because a table read from the medium, a table recovered from
/// its backup copy, and a table *made up* from a scan are three different
/// levels of evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutOrigin {
    /// Read from the partition table at the front of the medium: the GPT
    /// header at LBA 1 or the MBR at LBA 0.
    Table,
    /// Read from the GPT backup header in the last sector of the medium
    /// because the primary at LBA 1 was wiped or invalid. The entries are
    /// the disk's own; the front of the medium is what is damaged.
    BackupTable,
    /// Reconstructed by scanning the medium for filesystem starts with the
    /// given stride, ignoring any partition table. Synthetic: the ordinals
    /// hold only for the same medium scanned with the same stride, sizes are
    /// what each filesystem claims for itself, and there are no partition
    /// names or type GUIDs.
    Scan {
        /// Distance between the candidate positions the scan tested.
        stride: u64,
    },
    /// The medium holds no table; its single entry is the whole medium.
    None,
}

/// One mountable extent within a decoded medium or drive.
#[derive(Clone, Debug)]
pub struct LayoutPartition {
    /// Position in the listing, counting non-empty entries from 0. This is
    /// the number `--partition` and
    /// [`ImageOpenOptions::with_partition`](crate::ImageOpenOptions::with_partition)
    /// take.
    pub ordinal: usize,
    /// Byte offset of the partition start within the medium.
    pub offset: u64,
    /// Length of the partition in bytes, as declared by the partition table
    /// (or, for a scanned layout, as claimed by the filesystem itself).
    ///
    /// 0 means "unknown, and running to the end of the medium": only a
    /// drive whose size the operating system would not report can produce
    /// it, since nothing then bounds the extent.
    pub size_bytes: u64,
    /// How many of those bytes lie past the end of the medium.
    ///
    /// 0 when the partition is fully present, and also when the medium's
    /// own length is unknown — nothing can then be shown to be missing.
    /// Equal to [`size_bytes`](Self::size_bytes) when the partition starts
    /// past the end of the medium — a partition-table-only dump, or an
    /// acquisition that stopped early, describes extents the medium does
    /// not carry.
    pub missing_bytes: u64,
    /// Human-readable partition type: the GPT type name, or the MBR type
    /// name falling back to its `0xNN` code. `None` for a GPT type GUID
    /// with no known name and for media without a partition table.
    pub type_name: Option<String>,
    /// GPT partition label. Always `None` for MBR, which stores no labels.
    pub name: Option<String>,
    /// Filesystem detected at the partition start, or `None` when those
    /// bytes could not be read (a truncated or partition-table-only image).
    pub detected: Option<DetectedBootSector>,
}

impl LayoutPartition {
    /// Bytes of this partition the medium actually carries.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.size_bytes.saturating_sub(self.missing_bytes)
    }

    /// Whether the medium carries none of this partition at all.
    #[must_use]
    pub const fn is_beyond_end(&self) -> bool {
        self.available_bytes() == 0
    }

    /// Whether the medium carries some but not all of this partition.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.missing_bytes > 0 && !self.is_beyond_end()
    }
}

#[cfg(test)]
mod tests {
    use super::LayoutPartition;
    use super::media::missing_bytes;

    fn partition(offset: u64, size_bytes: u64, image_size: u64) -> LayoutPartition {
        LayoutPartition {
            ordinal: 0,
            offset,
            size_bytes,
            missing_bytes: missing_bytes(offset, size_bytes, Some(image_size)),
            type_name: None,
            name: None,
            detected: None,
        }
    }

    #[test]
    fn a_partition_inside_the_image_is_complete() {
        let partition = partition(1024, 4096, 65_536);
        assert_eq!(partition.missing_bytes, 0);
        assert_eq!(partition.available_bytes(), 4096);
        assert!(!partition.is_truncated());
        assert!(!partition.is_beyond_end());
    }

    #[test]
    fn a_partition_the_image_stops_inside_is_truncated() {
        let partition = partition(1024, 4096, 3072);
        assert_eq!(partition.missing_bytes, 2048);
        assert_eq!(partition.available_bytes(), 2048);
        assert!(partition.is_truncated());
        assert!(!partition.is_beyond_end());
    }

    #[test]
    fn a_partition_starting_past_the_end_is_missing_entirely() {
        let partition = partition(8192, 4096, 4096);
        assert_eq!(partition.missing_bytes, 4096);
        assert_eq!(partition.available_bytes(), 0);
        assert!(partition.is_beyond_end());
        assert!(!partition.is_truncated(), "nothing of it is present to cut");
    }

    #[test]
    fn a_partition_ending_exactly_at_the_end_is_complete() {
        let partition = partition(4096, 4096, 8192);
        assert_eq!(partition.missing_bytes, 0);
    }

    #[test]
    fn nothing_is_missing_from_a_medium_of_unknown_length() {
        assert_eq!(
            missing_bytes(8192, 4096, None),
            0,
            "a drive that reports no size cannot be shown to be short of anything"
        );
    }
}
