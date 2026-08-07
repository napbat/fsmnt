use std::path::{Path, PathBuf};

use crate::{HostDriveEnumerator, HostDriveId, HostDriveResult};

use super::BlockZoneReporter;

/// A byte range located on one physical drive.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PhysicalExtent {
    drive: HostDriveId,
    offset: u64,
    length: u64,
}

impl PhysicalExtent {
    /// Describe `length` bytes beginning at `offset` on `drive`.
    #[must_use]
    pub fn new(drive: HostDriveId, offset: u64, length: u64) -> Self {
        Self {
            drive,
            offset,
            length,
        }
    }

    /// Physical drive containing this extent.
    #[must_use]
    pub const fn drive(&self) -> &HostDriveId {
        &self.drive
    }

    /// Byte offset from the beginning of the physical drive.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Extent length in bytes.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Exclusive end offset, or `None` if the range overflows `u64`.
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }

    /// Whether another extent begins at the same byte on the same drive.
    ///
    /// Operating systems sometimes report a logical extent slightly shorter
    /// than its containing partition, so source resolution must not require
    /// the reported lengths to be identical.
    #[must_use]
    pub fn has_same_start(&self, other: &Self) -> bool {
        self.drive == other.drive && self.offset == other.offset
    }
}

/// A physical drive and partition-table ordinal supplied by a caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionAddress {
    drive: HostDriveId,
    partition: usize,
}

impl PartitionAddress {
    /// Select `partition` on `drive`.
    #[must_use]
    pub fn new(drive: HostDriveId, partition: usize) -> Self {
        Self { drive, partition }
    }

    /// Selected physical drive.
    #[must_use]
    pub const fn drive(&self) -> &HostDriveId {
        &self.drive
    }

    /// Zero-based ordinal over non-empty partition entries.
    #[must_use]
    pub const fn partition(&self) -> usize {
        self.partition
    }
}

/// Stable, platform-defined identifier for an operating-system logical volume.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalVolumeId(String);

impl LogicalVolumeId {
    /// Wrap a platform identifier such as a Windows volume GUID, Linux
    /// device-mapper UUID, or macOS BSD media name.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Identifier text supplied by the platform resolver.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogicalVolumeId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An operating-system logical volume and its physical provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalVolume {
    id: LogicalVolumeId,
    device_path: PathBuf,
    backing_extents: Vec<PhysicalExtent>,
    mount_points: Vec<PathBuf>,
    length: Option<u64>,
    sector_size: Option<u32>,
}

impl LogicalVolume {
    /// Create a logical-volume descriptor.
    #[must_use]
    pub fn new(
        id: LogicalVolumeId,
        device_path: PathBuf,
        backing_extents: Vec<PhysicalExtent>,
    ) -> Self {
        Self {
            id,
            device_path,
            backing_extents,
            mount_points: Vec::new(),
            length: None,
            sector_size: None,
        }
    }

    /// Attach the paths at which the operating system mounted this volume.
    #[must_use]
    pub fn with_mount_points(mut self, mount_points: Vec<PathBuf>) -> Self {
        self.mount_points = mount_points;
        self
    }

    /// Attach the logical volume's readable length.
    #[must_use]
    pub const fn with_length(mut self, length: u64) -> Self {
        self.length = Some(length);
        self
    }

    /// Attach the logical volume's reported sector size.
    #[must_use]
    pub const fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = Some(sector_size);
        self
    }

    /// Stable platform identifier.
    #[must_use]
    pub const fn id(&self) -> &LogicalVolumeId {
        &self.id
    }

    /// Platform device path used to open the logical block view.
    #[must_use]
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// Physical extents which contribute storage to this logical volume.
    #[must_use]
    pub fn backing_extents(&self) -> &[PhysicalExtent] {
        &self.backing_extents
    }

    /// Filesystem paths at which this logical volume is mounted.
    #[must_use]
    pub fn mount_points(&self) -> &[PathBuf] {
        &self.mount_points
    }

    /// Logical readable length when reported by the operating system.
    #[must_use]
    pub const fn length(&self) -> Option<u64> {
        self.length
    }

    /// Logical sector size reported by the operating system.
    #[must_use]
    pub const fn sector_size(&self) -> Option<u32> {
        self.sector_size
    }

    /// Whether this volume currently has at least one mount point.
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        !self.mount_points.is_empty()
    }

    /// Whether `extent` is one of this volume's physical backing ranges.
    #[must_use]
    pub fn is_backed_by(&self, extent: &PhysicalExtent) -> bool {
        self.backing_extents
            .iter()
            .any(|candidate| candidate.has_same_start(extent))
    }
}

/// Platform support for resolving physical extents into logical volumes.
pub trait HostVolumeResolver: HostDriveEnumerator {
    /// Reader type returned for operating-system logical block views.
    type VolumeReader: crate::DeviceReader + 'static;

    /// Discover logical volumes backed by `extent`.
    ///
    /// A result can contain several volumes, for example APFS volumes in one
    /// container or Linux logical volumes stacked above one physical volume.
    ///
    /// # Errors
    ///
    /// Returns an error if platform volume discovery fails.
    fn logical_volumes(extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>>;

    /// Create an on-demand zone reporter whose coordinates are relative to
    /// `extent`.
    ///
    /// The default implementation reports an ordinary non-zoned source.
    ///
    /// # Errors
    ///
    /// Returns an error when zone geometry exists but cannot be queried.
    fn physical_zone_reporter(
        _extent: &PhysicalExtent,
    ) -> HostDriveResult<Option<Box<dyn BlockZoneReporter>>> {
        Ok(None)
    }

    /// Open the operating system's logical block view of `volume`.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume disappeared, is locked, or cannot be
    /// opened for read-only access.
    fn open_logical_volume(volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader>;

    /// Create an on-demand zone reporter for an operating-system logical
    /// volume.
    ///
    /// The default implementation reports an ordinary non-zoned source.
    ///
    /// # Errors
    ///
    /// Returns an error when zone geometry exists but cannot be queried.
    fn logical_zone_reporter(
        _volume: &LogicalVolume,
    ) -> HostDriveResult<Option<Box<dyn BlockZoneReporter>>> {
        Ok(None)
    }
}

/// How a partition's filesystem source should be selected.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum SourceSelection {
    /// Select a unique readable operating-system logical volume.
    #[default]
    Auto,
    /// Select one logical volume by its platform identifier.
    Logical(LogicalVolumeId),
    /// Bypass operating-system logical volumes and open physical partitions.
    Raw {
        /// Additional raw partition members supplied explicitly.
        ///
        /// Filesystem drivers may discover other referenced members
        /// automatically across enumerated host drives.
        additional_partitions: Vec<PartitionAddress>,
    },
}

/// Provenance of an opened filesystem source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceOrigin {
    /// An operating-system logical block view.
    Logical(LogicalVolume),
    /// One or more directly opened physical partition extents.
    Raw(Vec<PhysicalExtent>),
}

/// Failure to choose one logical volume from discovered candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VolumeSelectionError {
    /// No logical volume is backed by the selected physical extent.
    NoneAvailable {
        /// Physical extent for which discovery returned no candidates.
        extent: PhysicalExtent,
    },
    /// An explicit logical-volume identifier did not match a candidate.
    NotFound {
        /// Requested logical-volume identifier.
        requested: LogicalVolumeId,
        /// Physical extent being resolved.
        extent: PhysicalExtent,
    },
    /// Automatic selection found several equally suitable candidates.
    Ambiguous {
        /// Candidate identifiers requiring an explicit choice.
        candidates: Vec<LogicalVolumeId>,
    },
}

impl std::fmt::Display for VolumeSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoneAvailable { extent } => {
                write!(
                    formatter,
                    "no operating-system logical volume is backed by {extent:?}"
                )
            }
            Self::NotFound { requested, extent } => {
                write!(
                    formatter,
                    "logical volume {requested} is not backed by {extent:?}"
                )
            }
            Self::Ambiguous { candidates } => {
                formatter.write_str("physical extent has several logical volumes: ")?;
                for (index, candidate) in candidates.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{candidate}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for VolumeSelectionError {}

/// Choose a logical volume according to `selection`.
///
/// Automatic selection prefers a sole mounted candidate. If none is mounted,
/// it accepts a sole discovered candidate. It never silently chooses between
/// several candidates.
///
/// # Errors
///
/// Returns [`VolumeSelectionError`] when no candidate exists, an explicit ID
/// is absent, or automatic selection remains ambiguous.
pub fn select_logical_volume(
    extent: &PhysicalExtent,
    candidates: &[LogicalVolume],
    selection: Option<&LogicalVolumeId>,
) -> Result<LogicalVolume, VolumeSelectionError> {
    if let Some(requested) = selection {
        return candidates
            .iter()
            .find(|candidate| candidate.id() == requested)
            .cloned()
            .ok_or_else(|| VolumeSelectionError::NotFound {
                requested: requested.clone(),
                extent: extent.clone(),
            });
    }

    let mounted: Vec<&LogicalVolume> = candidates
        .iter()
        .filter(|candidate| candidate.is_mounted())
        .collect();
    if let [candidate] = mounted.as_slice() {
        return Ok((*candidate).clone());
    }
    if mounted.len() > 1 {
        return Err(VolumeSelectionError::Ambiguous {
            candidates: mounted
                .into_iter()
                .map(|candidate| candidate.id().clone())
                .collect(),
        });
    }

    match candidates {
        [] => Err(VolumeSelectionError::NoneAvailable {
            extent: extent.clone(),
        }),
        [candidate] => Ok(candidate.clone()),
        many => Err(VolumeSelectionError::Ambiguous {
            candidates: many
                .iter()
                .map(|candidate| candidate.id().clone())
                .collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extent() -> PhysicalExtent {
        PhysicalExtent::new(HostDriveId::new("0"), 4096, 8192)
    }

    fn volume(id: &str, mounted: bool) -> LogicalVolume {
        let volume =
            LogicalVolume::new(LogicalVolumeId::new(id), PathBuf::from(id), vec![extent()]);
        if mounted {
            volume.with_mount_points(vec![PathBuf::from("/mnt/test")])
        } else {
            volume
        }
    }

    #[test]
    fn auto_selects_only_candidate() {
        let selected =
            select_logical_volume(&extent(), &[volume("one", false)], None).expect("selection");
        assert_eq!(selected.id().as_str(), "one");
    }

    #[test]
    fn auto_prefers_only_mounted_candidate() {
        let candidates = [volume("plain", false), volume("mounted", true)];
        let selected =
            select_logical_volume(&extent(), &candidates, None).expect("mounted selection");
        assert_eq!(selected.id().as_str(), "mounted");
    }

    #[test]
    fn auto_rejects_ambiguous_candidates() {
        let candidates = [volume("one", false), volume("two", false)];
        let error = select_logical_volume(&extent(), &candidates, None)
            .expect_err("ambiguous selection must fail");
        assert_eq!(
            error.to_string(),
            "physical extent has several logical volumes: one, two"
        );
    }

    #[test]
    fn explicit_selection_uses_identifier() {
        let candidates = [volume("one", true), volume("two", false)];
        let selected =
            select_logical_volume(&extent(), &candidates, Some(&LogicalVolumeId::new("two")))
                .expect("explicit selection");
        assert_eq!(selected.id().as_str(), "two");
    }

    #[test]
    fn backing_match_allows_platform_length_difference() {
        let volume = LogicalVolume::new(
            LogicalVolumeId::new("shorter"),
            PathBuf::from("shorter"),
            vec![PhysicalExtent::new(HostDriveId::new("0"), 4096, 4096)],
        );
        assert!(volume.is_backed_by(&PhysicalExtent::new(HostDriveId::new("0"), 4096, 8192,)));
    }
}
