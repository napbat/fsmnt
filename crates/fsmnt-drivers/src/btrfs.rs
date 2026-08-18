//! Read-only Btrfs adapter over the no_std-capable `fs-btrfs` parser.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs_btrfs::{
    Btrfs, BtrfsDeviceSource, BtrfsDirEntry, BtrfsEntry, BtrfsError, BtrfsFileType, BtrfsInode,
    BtrfsTimestamp, BtrfsZone, BtrfsZoneCondition, BtrfsZoneType, BtrfsZonedDevice,
    ZONED_SUPERBLOCK_LOG_OFFSETS, probe_zoned_superblock,
};
use fsmnt_core::{FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem};
use fsmnt_device::{
    BlockZone, BlockZoneCondition, BlockZoneType, DetectedBootSector, DeviceMember, DeviceReader,
    DeviceSet, FilesystemDriver, FilesystemMemberDiscovery, FilesystemMemberId,
    FilesystemOpenOptions, FilesystemRoot, reject_unsupported_recovery,
};

use crate::identity;

fn map_btrfs_error(error: BtrfsError, path: &str) -> FsError {
    match error {
        BtrfsError::Io(error) => FsError::Io(error),
        BtrfsError::NotFound => FsError::NotFound(path.to_string()),
        BtrfsError::NotADirectory => FsError::NotADirectory(path.to_string()),
        BtrfsError::NotAFile => FsError::NotAFile(path.to_string()),
        other => FsError::Filesystem(other.to_string()),
    }
}

fn btrfs_zoned_device(member: &DeviceMember) -> FsResult<Option<BtrfsZonedDevice>> {
    let Some(reporter) = member.zone_reporter() else {
        return Ok(None);
    };
    let zone_size = reporter.zone_size();
    let pair_size = zone_size
        .checked_mul(2)
        .ok_or_else(|| FsError::Filesystem("Btrfs zone-pair size overflowed".to_string()))?;
    let mut zones = Vec::new();
    for log_start in ZONED_SUPERBLOCK_LOG_OFFSETS {
        let pair_end = log_start
            .checked_add(pair_size)
            .ok_or_else(|| FsError::Filesystem("Btrfs zone-pair offset overflowed".to_string()))?;
        if member.length() != u64::MAX && pair_end > member.length() {
            continue;
        }
        let zone_entries = reporter.report_zones(log_start, 2).map_err(FsError::Io)?;
        if zone_entries.is_empty() && log_start != 0 {
            continue;
        }
        if zone_entries.len() != 2 {
            return Err(FsError::Filesystem(format!(
                "Btrfs superblock log at {log_start:#x} requires two zones, got {}",
                zone_entries.len()
            )));
        }
        zones.extend(zone_entries.into_iter().map(convert_zone));
    }
    BtrfsZonedDevice::new(zone_size, zones)
        .map(Some)
        .map_err(|error| map_btrfs_error(error, "<zones>"))
}

fn convert_zone(zone: BlockZone) -> BtrfsZone {
    BtrfsZone::new(
        zone.start(),
        zone.length(),
        zone.capacity(),
        zone.write_pointer(),
        match zone.zone_type() {
            BlockZoneType::Conventional => BtrfsZoneType::Conventional,
            BlockZoneType::SequentialWriteRequired => BtrfsZoneType::SequentialWriteRequired,
            BlockZoneType::SequentialWritePreferred => BtrfsZoneType::SequentialWritePreferred,
        },
        match zone.condition() {
            BlockZoneCondition::NotWritePointer => BtrfsZoneCondition::NotWritePointer,
            BlockZoneCondition::Empty => BtrfsZoneCondition::Empty,
            BlockZoneCondition::ImplicitOpen => BtrfsZoneCondition::ImplicitOpen,
            BlockZoneCondition::ExplicitOpen => BtrfsZoneCondition::ExplicitOpen,
            BlockZoneCondition::Closed => BtrfsZoneCondition::Closed,
            BlockZoneCondition::Active => BtrfsZoneCondition::Active,
            BlockZoneCondition::ReadOnly => BtrfsZoneCondition::ReadOnly,
            BlockZoneCondition::Full => BtrfsZoneCondition::Full,
            BlockZoneCondition::Offline => BtrfsZoneCondition::Offline,
        },
    )
}

fn btrfs_device_sources(
    devices: DeviceSet,
) -> FsResult<Vec<BtrfsDeviceSource<Box<dyn DeviceReader>>>> {
    let mut sources = Vec::with_capacity(devices.len());
    for member in devices.into_members() {
        let zoned = btrfs_zoned_device(&member)?;
        let mut source = BtrfsDeviceSource::new(member.into_reader());
        if let Some(zoned) = zoned {
            source = source.with_zoned_device(zoned);
        }
        sources.push(source);
    }
    Ok(sources)
}

fn btrfs_member_id(device_id: u64, device_uuid: &[u8; 16]) -> FilesystemMemberId {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&device_id.to_le_bytes());
    bytes.extend_from_slice(device_uuid);
    FilesystemMemberId::new(bytes)
}

fn inspect_btrfs_member(
    member: &mut DeviceMember,
    zoned: Option<BtrfsZonedDevice>,
) -> FsResult<FilesystemMemberDiscovery> {
    let original_position = member.reader_mut().stream_position()?;
    let parsed = {
        let mut source = BtrfsDeviceSource::new(member.reader_mut());
        if let Some(zoned) = zoned {
            source = source.with_zoned_device(zoned);
        }
        let mut volume = Btrfs::from_device_sources(vec![source])
            .map_err(|error| map_btrfs_error(error, "<member discovery>"))?;
        let inspected = btrfs_member_id(
            volume.superblock().device_id(),
            volume.superblock().device_uuid(),
        );
        let required = volume
            .discover_device_identities()
            .map_err(|error| map_btrfs_error(error, "<member discovery>"))?
            .into_iter()
            .map(|identity| btrfs_member_id(identity.device_id(), &identity.device_uuid()))
            .collect();
        Ok(FilesystemMemberDiscovery::new(
            DetectedBootSector::Btrfs,
            inspected,
            required,
        ))
    };
    let restored = member
        .reader_mut()
        .seek(SeekFrom::Start(original_position))
        .map(|_| ())
        .map_err(FsError::Io);
    match (parsed, restored) {
        (Ok(discovery), Ok(())) => Ok(discovery),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn canonicalise_btrfs_path(path: &str) -> Vec<&str> {
    let mut components = Vec::new();
    for component in path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
    {
        match component {
            "." => {}
            ".." => {
                components.pop();
            }
            name => components.push(name),
        }
    }
    components
}

fn timestamp_to_utc(timestamp: BtrfsTimestamp) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(timestamp.seconds(), timestamp.nanoseconds())
}

fn metadata_of(inode: &BtrfsInode) -> FsMetadata {
    let is_dir = inode.file_type().is_directory();
    FsMetadata {
        size: if is_dir { 0 } else { inode.size() },
        is_dir,
        created: timestamp_to_utc(inode.created()),
        modified: timestamp_to_utc(inode.modified()),
        accessed: timestamp_to_utc(inode.accessed()),
        readonly: inode.mode() & 0o222 == 0,
        hidden: false,
        system: false,
    }
}

fn entry_flags(file_type: BtrfsFileType, inode: &BtrfsInode) -> FsEntryFlags {
    let mut flags = FsEntryFlags::empty();
    if file_type.is_symbolic_link() {
        flags.insert(FsEntryFlags::REPARSE_POINT);
    }
    if inode.link_count() > 1 {
        flags.insert(FsEntryFlags::HARD_LINK);
    }
    flags
}

/// A raw Btrfs volume exposed through [`TargetFilesystem`].
pub struct BtrfsFilesystem<R: fs_btrfs::io::Read + fs_btrfs::io::Seek> {
    volume: Btrfs<R>,
    root: BtrfsEntry,
}

impl<R: fs_btrfs::io::Read + fs_btrfs::io::Seek> BtrfsFilesystem<R> {
    /// Open and fully bootstrap one Btrfs device.
    ///
    /// # Errors
    ///
    /// Returns an error when the superblock, chunk mapping, root tree, default
    /// subvolume, or root inode cannot be read and validated.
    pub fn new(reader: R) -> FsResult<Self> {
        Self::new_with_root(reader, &FilesystemRoot::Default)
    }

    /// Open one Btrfs device and select the mounted filesystem root.
    ///
    /// # Errors
    ///
    /// Returns an error when the volume cannot be bootstrapped or the selected
    /// root does not exist or is not meaningful for Btrfs.
    pub fn new_with_root(reader: R, root: &FilesystemRoot) -> FsResult<Self> {
        Self::from_volume(
            Btrfs::new(reader).map_err(|error| map_btrfs_error(error, "<open>"))?,
            root,
        )
    }

    /// Open and fully bootstrap every member of a Btrfs filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, duplicate, foreign, unreadable, or
    /// structurally invalid device members.
    pub fn from_devices(readers: Vec<R>) -> FsResult<Self> {
        Self::from_devices_with_root(readers, &FilesystemRoot::Default)
    }

    /// Open all Btrfs members and select the mounted filesystem root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid members, bootstrap failures, or an absent
    /// or incompatible root selection.
    pub fn from_devices_with_root(readers: Vec<R>, root: &FilesystemRoot) -> FsResult<Self> {
        Self::from_volume(
            Btrfs::from_devices(readers).map_err(|error| map_btrfs_error(error, "<open>"))?,
            root,
        )
    }

    /// Open Btrfs members carrying explicit conventional or zoned geometry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid member geometry, bootstrap failures, or an
    /// absent default root.
    pub fn from_device_sources(sources: Vec<BtrfsDeviceSource<R>>) -> FsResult<Self> {
        Self::from_device_sources_with_root(sources, &FilesystemRoot::Default)
    }

    /// Open Btrfs members carrying explicit source geometry and select a root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid members, bootstrap failures, or an absent
    /// or incompatible root selection.
    pub fn from_device_sources_with_root(
        sources: Vec<BtrfsDeviceSource<R>>,
        root: &FilesystemRoot,
    ) -> FsResult<Self> {
        Self::from_volume(
            Btrfs::from_device_sources(sources)
                .map_err(|error| map_btrfs_error(error, "<open>"))?,
            root,
        )
    }

    fn from_volume(mut volume: Btrfs<R>, root: &FilesystemRoot) -> FsResult<Self> {
        volume
            .initialize()
            .map_err(|error| map_btrfs_error(error, "<bootstrap>"))?;
        let root = match root {
            FilesystemRoot::Default => volume.root(),
            FilesystemRoot::TopLevel => volume.top_level_root(),
            FilesystemRoot::Id(tree_id) => volume.subvolume_root(*tree_id),
            FilesystemRoot::Path(path) => {
                let components = canonicalise_btrfs_path(path);
                volume.subvolume_at_path(components.iter().map(|component| component.as_bytes()))
            }
            FilesystemRoot::Index(_) | FilesystemRoot::Name(_) | FilesystemRoot::Role(_) => {
                return Err(FsError::Filesystem(format!(
                    "Btrfs does not support root selector {root:?}"
                )));
            }
        }
        .map_err(|error| map_btrfs_error(error, "<subvolume>"))?;
        Ok(Self { volume, root })
    }

    /// Access the format parser.
    #[must_use]
    pub const fn volume(&self) -> &Btrfs<R> {
        &self.volume
    }

    /// Root selected for this mounted view.
    #[must_use]
    pub const fn selected_root(&self) -> BtrfsEntry {
        self.root
    }

    fn resolve(&mut self, path: &str) -> FsResult<BtrfsEntry> {
        let components = canonicalise_btrfs_path(path);
        self.volume
            .resolve_path_from(
                self.root,
                components.iter().map(|component| component.as_bytes()),
            )
            .map_err(|error| map_btrfs_error(error, path))
    }

    fn directory_entry(
        &mut self,
        parent: &Path,
        raw: &BtrfsDirEntry,
        source_path: &str,
    ) -> FsResult<FsEntry> {
        let inode = self
            .volume
            .inode(raw.entry())
            .map_err(|error| map_btrfs_error(error, source_path))?;
        let name = String::from_utf8_lossy(raw.name()).into_owned();
        Ok(FsEntry {
            path: parent.join(&name),
            name,
            flags: entry_flags(inode.file_type(), &inode),
            file_id: Some(raw.entry().object_id()),
            metadata: metadata_of(&inode),
        })
    }
}

impl<R: fs_btrfs::io::Read + fs_btrfs::io::Seek + Send> TargetFilesystem for BtrfsFilesystem<R> {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let entry = self.resolve(path)?;
        self.volume
            .read_file(entry)
            .map_err(|error| map_btrfs_error(error, path))
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        let entry = self.resolve(path)?;
        self.volume
            .read_file_range(entry, offset, buffer)
            .map_err(|error| map_btrfs_error(error, path))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        match self.resolve(path) {
            Ok(_) => Ok(true),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        match self.metadata(path) {
            Ok(metadata) => Ok(metadata.is_dir),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        match self.metadata(path) {
            Ok(metadata) => Ok(!metadata.is_dir),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let entry = self.resolve(path)?;
        let inode = self
            .volume
            .inode(entry)
            .map_err(|error| map_btrfs_error(error, path))?;
        Ok(metadata_of(&inode))
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let directory = self.resolve(path)?;
        let raw_entries = self
            .volume
            .read_dir(directory)
            .map_err(|error| map_btrfs_error(error, path))?;
        let normalized = canonicalise_btrfs_path(path).join("/");
        let parent = if normalized.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(normalized)
        };
        raw_entries
            .into_iter()
            .map(|entry| self.directory_entry(&parent, &entry, path))
            .collect()
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.volume.superblock().total_bytes())
    }

    fn free_space(&mut self) -> Option<u64> {
        Some(
            self.volume
                .superblock()
                .total_bytes()
                .saturating_sub(self.volume.superblock().bytes_used()),
        )
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::uuid(self.volume.superblock().fsid()))
    }
}

/// Driver for read-only Btrfs volumes, including native multi-device layouts.
#[derive(Clone, Copy, Debug, Default)]
pub struct BtrfsDriver;

impl FilesystemDriver for BtrfsDriver {
    fn name(&self) -> &'static str {
        "btrfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Btrfs
    }

    fn probe_devices(
        &self,
        devices: &mut DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Option<DetectedBootSector>> {
        if self.supports(detected) {
            return Ok(Some(DetectedBootSector::Btrfs));
        }
        if detected != DetectedBootSector::Unknown {
            return Ok(None);
        }
        let Some(zoned) = btrfs_zoned_device(devices.primary())? else {
            return Ok(None);
        };
        match probe_zoned_superblock(devices.primary_mut().reader_mut(), &zoned) {
            Ok(true) => Ok(Some(DetectedBootSector::Btrfs)),
            Ok(false) | Err(BtrfsError::ZonedSuperblockNotFound) => Ok(None),
            Err(error) => Err(map_btrfs_error(error, "<probe>")),
        }
    }

    fn discover_members(
        &self,
        member: &mut DeviceMember,
        detected: DetectedBootSector,
    ) -> FsResult<Option<FilesystemMemberDiscovery>> {
        if detected != DetectedBootSector::Btrfs && detected != DetectedBootSector::Unknown {
            return Ok(None);
        }
        let zoned = btrfs_zoned_device(member)?;
        if detected == DetectedBootSector::Unknown {
            let Some(zoned_device) = zoned.as_ref() else {
                return Ok(None);
            };
            match probe_zoned_superblock(member.reader_mut(), zoned_device) {
                Ok(true) => {}
                Ok(false) | Err(BtrfsError::ZonedSuperblockNotFound) => return Ok(None),
                Err(error) => return Err(map_btrfs_error(error, "<member discovery>")),
            }
        }
        inspect_btrfs_member(member, zoned).map(Some)
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(BtrfsFilesystem::new(reader)?))
    }

    fn open_with_options(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        reject_unsupported_recovery(self.name(), options)?;
        Ok(Box::new(BtrfsFilesystem::new_with_root(
            reader,
            options.root(),
        )?))
    }

    fn open_devices(
        &self,
        devices: DeviceSet,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(BtrfsFilesystem::from_device_sources(
            btrfs_device_sources(devices)?,
        )?))
    }

    fn open_devices_with_options(
        &self,
        devices: DeviceSet,
        _detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        reject_unsupported_recovery(self.name(), options)?;
        Ok(Box::new(BtrfsFilesystem::from_device_sources_with_root(
            btrfs_device_sources(devices)?,
            options.root(),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    struct StaticZoneReporter {
        zones: Vec<BlockZone>,
    }

    impl fsmnt_device::BlockZoneReporter for StaticZoneReporter {
        fn zone_size(&self) -> u64 {
            fs_btrfs::MIN_ZONE_SIZE
        }

        fn report_zones(&self, start: u64, maximum: usize) -> io::Result<Vec<BlockZone>> {
            Ok(self
                .zones
                .iter()
                .copied()
                .filter(|zone| zone.start() >= start)
                .take(maximum)
                .collect())
        }
    }

    fn empty_zoned_member() -> DeviceMember {
        let zone_size = fs_btrfs::MIN_ZONE_SIZE;
        let reporter = StaticZoneReporter {
            zones: vec![
                BlockZone::new(
                    0,
                    zone_size,
                    zone_size,
                    0,
                    BlockZoneType::SequentialWriteRequired,
                    BlockZoneCondition::Empty,
                ),
                BlockZone::new(
                    zone_size,
                    zone_size,
                    zone_size,
                    zone_size,
                    BlockZoneType::SequentialWriteRequired,
                    BlockZoneCondition::Empty,
                ),
            ],
        };
        DeviceMember::new(
            fsmnt_device::SourceMemberId::Synthetic("zoned".to_string()),
            Box::new(std::io::Cursor::new(vec![
                0_u8;
                usize::try_from(2 * zone_size)
                    .expect(
                        "test image size fits usize"
                    )
            ])),
            2 * zone_size,
            4096,
        )
        .expect("device member")
        .with_zone_reporter(Box::new(reporter))
    }

    #[test]
    fn driver_supports_only_btrfs() {
        let driver = BtrfsDriver;
        assert!(driver.supports(DetectedBootSector::Btrfs));
        for other in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
            DetectedBootSector::BitLocker,
            DetectedBootSector::GptPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(!driver.supports(other), "driver must not claim {other:?}");
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(BtrfsDriver.name(), "btrfs");
    }

    #[test]
    fn path_resolution_preserves_btrfs_filename_bytes() {
        assert_eq!(
            canonicalise_btrfs_path("/a\\b/C:literal/./child/../tail"),
            ["a\\b", "C:literal", "tail"]
        );
    }

    #[test]
    fn invalid_superblock_is_reported_before_bootstrap() {
        let reader = Box::new(std::io::Cursor::new(vec![0_u8; 0x1_1000]));
        let Err(error) = BtrfsDriver.open(reader, DetectedBootSector::Btrfs) else {
            panic!("zeroed superblock must fail");
        };

        assert!(error.to_string().contains("invalid Btrfs magic"), "{error}");
    }

    #[test]
    fn generic_zone_report_maps_to_btrfs_geometry() {
        let member = empty_zoned_member();
        let zoned = btrfs_zoned_device(&member)
            .expect("map zone report")
            .expect("zoned source");
        assert_eq!(zoned.zone_size(), fs_btrfs::MIN_ZONE_SIZE);
        assert_eq!(zoned.zones().len(), 2);
        assert_eq!(
            zoned.zones()[0].zone_type(),
            BtrfsZoneType::SequentialWriteRequired
        );
        assert_eq!(zoned.zones()[1].condition(), BtrfsZoneCondition::Empty);
    }

    #[test]
    fn empty_zoned_log_does_not_claim_an_unknown_device() {
        let mut devices = DeviceSet::new(empty_zoned_member());
        assert!(
            BtrfsDriver
                .probe_devices(&mut devices, DetectedBootSector::Unknown)
                .expect("probe empty zoned source")
                .is_none()
        );
    }
}
