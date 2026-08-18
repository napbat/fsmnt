//! What a scan found, and what can be done with it.
//!
//! A hit is a claim about some bytes, and the claims differ in what they
//! license. The start of a filesystem is an offset a mount can be pointed
//! at; a partition table describes filesystems rather than being one; a
//! backup superblock is evidence *about* a filesystem whose start may lie
//! elsewhere on the medium — or before it, when the medium is a slice cut
//! out of one. Keeping those distinctions in the type, and in
//! [`ScanHit::mount_offset`] and [`ScanHit::head_absent`], is what stops a
//! listing from offering a command that cannot work.

use fsmnt_device::DetectedBootSector;

/// What a scan found at one offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanHit {
    /// Byte offset in the medium. For a filesystem this is the offset to
    /// hand to `fsmnt mount SOURCE --offset`; for a backup superblock it is
    /// where the copy itself sits, not where its filesystem starts.
    pub offset: u64,
    /// What the bytes at `offset` are.
    pub kind: ScanHitKind,
    /// Size the structure claims for its filesystem, where the format states
    /// one. Not a measurement — a truncated image reports the size the
    /// superblock was written with.
    pub size_bytes: Option<u64>,
    /// Backup superblocks found inside this filesystem, in offset order.
    /// Only ever populated for an ext filesystem hit.
    pub backup_superblocks: Vec<ExtBackupSuperblock>,
}

impl ScanHit {
    /// The offset `fsmnt mount SOURCE --offset` would take for this hit, if
    /// it is mountable at all.
    ///
    /// A partition table is not mountable, and a stray backup superblock is
    /// mountable only at the filesystem start it implies — never at its own
    /// offset, which the ext driver refuses on purpose. Superblock copies
    /// that no backup corroborates are not mountable either: nothing says a
    /// filesystem begins where they sit.
    #[must_use]
    pub fn mount_offset(&self) -> Option<u64> {
        match self.kind {
            ScanHitKind::Filesystem(_) => Some(self.offset),
            ScanHitKind::ExtBackupSuperblock {
                filesystem_start, ..
            } => filesystem_start,
            ScanHitKind::ExtPrimaryCopies { .. } => {
                (!self.backup_superblocks.is_empty()).then_some(self.offset)
            }
            ScanHitKind::PartitionTable(_) => None,
        }
    }

    /// Bytes of this hit's filesystem that lie *before* the medium, when
    /// the medium is a slice cut out of the middle of one.
    ///
    /// A backup superblock records the geometry of its filesystem, so a
    /// copy found at some offset says where its filesystem began — and
    /// that answer is sometimes a negative offset, meaning the acquisition
    /// started after the volume did. There is then no offset on this medium
    /// to mount at, which is why [`mount_offset`](Self::mount_offset) stays
    /// `None`; the volume is still openable, by declaring the absent head
    /// (`--offset -N`, or
    /// [`ImageOpenOptions::with_head_absent`](crate::ImageOpenOptions::with_head_absent))
    /// and opening through one of the copies that *are* present.
    #[must_use]
    pub const fn head_absent(&self) -> Option<u64> {
        match self.kind {
            ScanHitKind::ExtBackupSuperblock {
                start_before_medium,
                ..
            } => start_before_medium,
            ScanHitKind::Filesystem(_)
            | ScanHitKind::PartitionTable(_)
            | ScanHitKind::ExtPrimaryCopies { .. } => None,
        }
    }

    /// The block group of the first surviving backup superblock, which is
    /// what `--backup-superblock` takes to open the volume.
    ///
    /// For a lone backup that is the copy this hit *is*; for a filesystem
    /// hit it is the first copy corroborating it.
    #[must_use]
    pub fn backup_superblock_group(&self) -> Option<u32> {
        if let ScanHitKind::ExtBackupSuperblock { group, .. } = self.kind {
            return Some(u32::from(group));
        }
        self.backup_superblocks
            .first()
            .map(|backup| u32::from(backup.group))
    }
}

/// The hits a scan numbers for `fsmnt mount SOURCE --scan --partition N`:
/// every hit with a [`mount_offset`](ScanHit::mount_offset), in scan order.
///
/// The number is **synthetic** — it comes from this scan of this medium with
/// these options, not from any partition table on it — so it holds only for
/// the same medium scanned with the same stride. It is a convenience over
/// pasting the offset, not an identity of the volume.
///
/// Evidence a scan cannot act on is deliberately absent: a partition table,
/// a backup superblock whose filesystem starts before this medium, and a
/// superblock copy nothing corroborates all appear in the hit list and none
/// of them gets a number, because there is no offset to hand a mount. The
/// middle case is still mountable, just not by an offset into this medium —
/// see [`ScanHit::head_absent`].
#[must_use]
pub fn mountable_hits(hits: &[ScanHit]) -> Vec<&ScanHit> {
    hits.iter()
        .filter(|hit| hit.mount_offset().is_some())
        .collect()
}

/// The kind of structure a [`ScanHit`] identifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanHitKind {
    /// The start of a filesystem of this type.
    Filesystem(DetectedBootSector),
    /// A partition table, which describes filesystems rather than being one.
    PartitionTable(DetectedBootSector),
    /// Backup superblock(s) of an ext filesystem whose primary this scan did
    /// not confirm.
    ///
    /// [`ScanHit::offset`] is the first copy; the other copies of the same
    /// filesystem that agree on the start are in
    /// [`ScanHit::backup_superblocks`].
    ExtBackupSuperblock {
        /// Block group the first copy belongs to.
        group: u16,
        /// Offset its filesystem would have started at, or `None` when that
        /// would fall before the start of the media.
        filesystem_start: Option<u64>,
        /// Bytes by which the implied start precedes the medium — the medium
        /// is a slice that begins inside the filesystem. `Some` exactly when
        /// `filesystem_start` is `None`.
        start_before_medium: Option<u64>,
    },
    /// Copies of an ext primary superblock (group 0) with no filesystem
    /// behind them: block 0 journalled inside a filesystem, or a start whose
    /// metadata is damaged.
    ///
    /// A copy fails either of the two tests a start passes — no group
    /// descriptor table follows it, or one does but the root inode it points
    /// at is not a directory, which is what block 0 and block 1 journalled
    /// together look like.
    ///
    /// [`ScanHit::offset`] is the first, `last_offset` the last, `copies` how
    /// many. Backups that name `offset` as their filesystem's start land in
    /// [`ScanHit::backup_superblocks`], and only then is the hit mountable.
    ExtPrimaryCopies {
        /// How many copies were folded into this one hit.
        copies: usize,
        /// Offset of the last copy, so the run's extent is on record.
        last_offset: u64,
    },
}

/// An ext superblock copy found inside a filesystem the scan also located.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtBackupSuperblock {
    /// Byte offset of the copy in the decoded media.
    pub offset: u64,
    /// Block group it belongs to.
    pub group: u16,
}
