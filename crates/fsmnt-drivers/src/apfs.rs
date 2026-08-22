//! APFS adapter over the vendored `fs-apfs` parser.
//!
//! An APFS *container* can hold several *volumes*; [`ApfsFilesystem`]
//! selects one — by default the Data-role volume, the modern macOS
//! user-data volume — and exposes its file tree through
//! [`TargetFilesystem`]. [`ApfsDriver`] registers it for
//! [`DetectedBootSector::Apfs`].
//!
//! `decmpfs`-compressed files and `FileVault`-encrypted volumes surface as
//! typed errors rather than as empty or garbage data.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs_apfs::{
    Apfs, ApfsError, ApfsSuperblock, ApfsTimestamp, DataStream, DirEntry, DirEntryType,
    ExtendedFields, File, FileType, Inode, Volume, VolumeRole, Xattr,
};
use fsmnt_core::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, OpenedDirectory, OpenedFile,
    OpenedTarget, TargetFilesystem,
};
use fsmnt_device::{
    DetectedBootSector, DeviceReader, FilesystemDriver, FilesystemOpenOptions, FilesystemRoot,
    reject_unsupported_recovery,
};
use tracing::debug;

use crate::identity;

use crate::adapter::{PathCache, found};

/// The extended attribute that marks a `decmpfs`-compressed file.
const DECMPFS_XATTR: &str = "com.apple.decmpfs";

/// Selects which volume of an APFS container the adapter opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeSelector {
    /// Pick automatically — prefer the Data role, then System, else the
    /// first volume.
    Auto,
    /// The volume at this index in the container's volume list.
    Index(usize),
    /// The first volume with this role.
    Role(VolumeRole),
    /// The first volume with this exact name.
    Name(String),
}

fn parse_volume_role(role: &str) -> Option<VolumeRole> {
    match role.to_ascii_lowercase().as_str() {
        "none" => Some(VolumeRole::None),
        "system" => Some(VolumeRole::System),
        "user" => Some(VolumeRole::User),
        "recovery" => Some(VolumeRole::Recovery),
        "vm" => Some(VolumeRole::Vm),
        "preboot" => Some(VolumeRole::Preboot),
        "installer" => Some(VolumeRole::Installer),
        "data" => Some(VolumeRole::Data),
        "baseband" => Some(VolumeRole::Baseband),
        "update" => Some(VolumeRole::Update),
        "xart" => Some(VolumeRole::Xart),
        "hardware" => Some(VolumeRole::Hardware),
        "backup" => Some(VolumeRole::Backup),
        "enterprise" => Some(VolumeRole::Enterprise),
        "prelogin" => Some(VolumeRole::Prelogin),
        _ => None,
    }
}

fn requested_volume(root: &FilesystemRoot) -> FsResult<VolumeSelector> {
    match root {
        FilesystemRoot::Default => Ok(VolumeSelector::Auto),
        FilesystemRoot::Index(index) => Ok(VolumeSelector::Index(*index)),
        FilesystemRoot::Name(name) => Ok(VolumeSelector::Name(name.clone())),
        FilesystemRoot::Role(role) => parse_volume_role(role)
            .map(VolumeSelector::Role)
            .ok_or_else(|| FsError::Filesystem(format!("unknown APFS volume role {role:?}"))),
        FilesystemRoot::TopLevel | FilesystemRoot::Path(_) | FilesystemRoot::Id(_) => Err(
            FsError::Filesystem(format!("APFS does not support root selector {root:?}")),
        ),
    }
}

/// Map an [`ApfsError`] onto the closest [`FsError`] variant.
fn map_apfs_error(error: ApfsError, path: &str) -> FsError {
    match error {
        ApfsError::NotFound { .. } => FsError::NotFound(path.to_string()),
        ApfsError::Io(io_err) => FsError::Io(io_err),
        other => FsError::Filesystem(format!("{other}")),
    }
}

/// Convert an APFS timestamp to UTC, mapping the zero ("unset") value and
/// out-of-range values to `None`.
fn ts_to_utc(ts: ApfsTimestamp) -> Option<DateTime<Utc>> {
    if ts.is_zero() { None } else { ts.to_chrono() }
}

/// Choose the volume index for `selector` from a container's volumes.
///
/// `Auto` prefers the Data-role volume (the modern split-volume layout),
/// then a System-role volume, and otherwise the first volume.
///
/// # Errors
///
/// Returns an error if the container has no volumes or the selector
/// matches none of them.
fn select_volume_index(volumes: &[ApfsSuperblock], selector: &VolumeSelector) -> FsResult<usize> {
    if volumes.is_empty() {
        return Err(FsError::Filesystem(
            "APFS container has no volumes".to_string(),
        ));
    }
    match selector {
        VolumeSelector::Auto => Ok(volumes
            .iter()
            .position(|v| v.role == VolumeRole::Data)
            .or_else(|| volumes.iter().position(|v| v.role == VolumeRole::System))
            .unwrap_or(0)),
        VolumeSelector::Index(index) => {
            if *index < volumes.len() {
                Ok(*index)
            } else {
                Err(FsError::Filesystem(format!(
                    "APFS volume index {index} out of range (container has {})",
                    volumes.len()
                )))
            }
        }
        VolumeSelector::Role(role) => volumes
            .iter()
            .position(|v| v.role == *role)
            .ok_or_else(|| FsError::Filesystem(format!("no APFS volume with role {role:?}"))),
        VolumeSelector::Name(name) => volumes
            .iter()
            .position(|v| &v.name == name)
            .ok_or_else(|| FsError::Filesystem(format!("no APFS volume named {name:?}"))),
    }
}

/// Build [`FsMetadata`] from an APFS inode.
fn metadata_of(inode: &Inode, size: u64) -> FsMetadata {
    FsMetadata {
        size,
        is_dir: inode.is_directory(),
        created: ts_to_utc(inode.created()),
        modified: ts_to_utc(inode.modified()),
        accessed: ts_to_utc(inode.accessed()),
        readonly: false,
        hidden: false,
        system: false,
    }
}

struct CachedApfsTarget {
    obj_id: u64,
    inode: Option<Inode>,
    metadata: Option<FsMetadata>,
    file: Option<File>,
}

impl CachedApfsTarget {
    const fn new(obj_id: u64) -> Self {
        Self {
            obj_id,
            inode: None,
            metadata: None,
            file: None,
        }
    }
}

/// One volume of a raw APFS container exposed as a [`TargetFilesystem`].
pub struct ApfsFilesystem<R: Read + Seek + Send> {
    reader: R,
    volume: Volume,
    volume_uuid: [u8; 16],
    block_size: u32,
    total_size: u64,
    /// Most recently resolved path and its incrementally populated state.
    resolved: PathCache<CachedApfsTarget>,
}

impl<R: Read + Seek + Send> ApfsFilesystem<R> {
    /// Open an APFS container and its automatically selected volume.
    ///
    /// # Errors
    ///
    /// Returns an error when the container cannot be mounted, has no
    /// volumes, or the selected volume is `FileVault`-encrypted.
    pub fn new(reader: R) -> FsResult<Self> {
        Self::open(reader, &VolumeSelector::Auto)
    }

    /// Open an APFS container, choosing a volume with `selector`.
    ///
    /// # Errors
    ///
    /// Returns an error when the container cannot be mounted, the selector
    /// matches no volume, or the selected volume is `FileVault`-encrypted.
    pub fn open(mut reader: R, selector: &VolumeSelector) -> FsResult<Self> {
        let apfs = Apfs::new(&mut reader).map_err(|e| map_apfs_error(e, "<container>"))?;
        let volumes = apfs
            .volumes(&mut reader)
            .map_err(|e| map_apfs_error(e, "<volumes>"))?;
        let index = select_volume_index(&volumes, selector)?;
        let superblock = &volumes[index];
        if superblock.is_encrypted() {
            return Err(FsError::Filesystem(format!(
                "APFS volume '{}' is FileVault-encrypted; a key is required \
                 and key-based unlock is not supported",
                superblock.name
            )));
        }
        let block_size = apfs.block_size();
        let total_size = apfs.block_count().saturating_mul(u64::from(block_size));
        let volume_uuid = superblock.vol_uuid.0;
        debug!(
            volume = %superblock.name,
            role = ?superblock.role,
            index,
            volumes = volumes.len(),
            block_size,
            size_bytes = total_size,
            "opened an APFS volume from its container"
        );
        let volume =
            Volume::open(&apfs, &mut reader, index).map_err(|e| map_apfs_error(e, "<volume>"))?;
        Ok(Self {
            reader,
            volume,
            volume_uuid,
            block_size,
            total_size,
            resolved: PathCache::new(),
        })
    }

    /// Resolve a path to its APFS object identifier.
    fn navigate(&mut self, path: &str) -> FsResult<u64> {
        if let Some(cached) = self.resolved.get(path) {
            return Ok(cached.obj_id);
        }
        let obj_id = self
            .volume
            .resolve_path(&mut self.reader, path)
            .map_err(|e| map_apfs_error(e, path))?;
        self.resolved.insert(path, CachedApfsTarget::new(obj_id));
        Ok(obj_id)
    }

    /// Populate the active path's inode once.
    fn cache_inode(&mut self, path: &str) -> FsResult<()> {
        let obj_id = self.navigate(path)?;
        if self
            .resolved
            .get(path)
            .is_some_and(|cached| cached.inode.is_some())
        {
            return Ok(());
        }
        let inode = self
            .volume
            .inode(&mut self.reader, obj_id)
            .map_err(|e| map_apfs_error(e, path))?
            .ok_or_else(|| FsError::NotFound(path.to_string()))?;
        self.resolved
            .get_mut(path)
            .ok_or_else(|| FsError::Filesystem("APFS path cache was not populated".to_string()))?
            .inode = Some(inode);
        Ok(())
    }

    /// The logical data-stream size in an inode's extended fields, or zero
    /// when the inode carries no data stream.
    fn data_stream_size(inode: &Inode) -> FsResult<u64> {
        let fields =
            ExtendedFields::parse(&inode.xfields).map_err(|e| map_apfs_error(e, "<xfields>"))?;
        match fields.dstream() {
            Some(bytes) => Ok(DataStream::parse(bytes)
                .map_err(|e| map_apfs_error(e, "<dstream>"))?
                .size),
            None => Ok(0),
        }
    }

    /// Opens and caches the regular file at `path`.
    ///
    /// A mount backend normally issues many positioned reads for one open
    /// file. Retaining only the most recent handle avoids repeating path,
    /// inode, xattr, and extent-tree walks while keeping cache memory bounded.
    fn cache_regular_file(&mut self, path: &str) -> FsResult<()> {
        self.cache_inode(path)?;
        if self
            .resolved
            .get(path)
            .is_some_and(|cached| cached.file.is_some())
        {
            return Ok(());
        }

        let (obj_id, file_type, private_id, size) = {
            let cached = self.resolved.get(path).ok_or_else(|| {
                FsError::Filesystem("APFS path cache was not populated".to_string())
            })?;
            let inode = cached.inode.as_ref().ok_or_else(|| {
                FsError::Filesystem("APFS inode cache was not populated".to_string())
            })?;
            (
                cached.obj_id,
                inode.file_type(),
                inode.private_id,
                Self::data_stream_size(inode)?,
            )
        };
        if file_type != FileType::Regular {
            return Err(FsError::NotAFile(path.to_string()));
        }
        if Xattr::contains_name(
            self.volume.catalog(),
            &mut self.reader,
            obj_id,
            DECMPFS_XATTR,
        )
        .map_err(|e| map_apfs_error(e, path))?
        {
            return Err(FsError::Filesystem(format!(
                "'{path}' uses decmpfs transparent compression, which is not supported"
            )));
        }
        let file = File::open(self.volume.catalog(), &mut self.reader, private_id, size)
            .map_err(|e| map_apfs_error(e, path))?;
        self.resolved
            .get_mut(path)
            .ok_or_else(|| FsError::Filesystem("APFS path cache was not populated".to_string()))?
            .file = Some(file);
        Ok(())
    }

    /// Return and retain mount-facing metadata for the active path.
    fn metadata_at(&mut self, path: &str) -> FsResult<FsMetadata> {
        self.cache_inode(path)?;
        if let Some(metadata) = self
            .resolved
            .get(path)
            .and_then(|cached| cached.metadata.clone())
        {
            return Ok(metadata);
        }
        let metadata = {
            let inode = self
                .resolved
                .get(path)
                .and_then(|cached| cached.inode.as_ref())
                .ok_or_else(|| {
                    FsError::Filesystem("APFS inode cache was not populated".to_string())
                })?;
            let size = if inode.is_directory() {
                0
            } else {
                Self::data_stream_size(inode)?
            };
            metadata_of(inode, size)
        };
        self.resolved
            .get_mut(path)
            .ok_or_else(|| FsError::Filesystem("APFS path cache was not populated".to_string()))?
            .metadata = Some(metadata.clone());
        Ok(metadata)
    }

    /// Convert an APFS [`DirEntry`] to an [`FsEntry`].
    ///
    /// The child inode is looked up best-effort: on failure the entry still
    /// appears, classified by the directory record's own type byte, so one
    /// unreadable inode never aborts a listing.
    fn entry_to_fs_entry(&mut self, parent: &Path, entry: DirEntry) -> FsEntry {
        let mut flags = FsEntryFlags::empty();
        if entry.file_type == DirEntryType::Symlink {
            flags |= FsEntryFlags::REPARSE_POINT;
        }

        let metadata = match self.volume.inode(&mut self.reader, entry.file_id) {
            Ok(Some(inode)) => {
                let size = if inode.is_directory() {
                    0
                } else {
                    Self::data_stream_size(&inode).unwrap_or(0)
                };
                metadata_of(&inode, size)
            }
            _ => FsMetadata {
                is_dir: entry.file_type == DirEntryType::Directory,
                ..FsMetadata::default()
            },
        };

        let name = entry.name;
        FsEntry {
            path: parent.join(&name),
            name,
            flags,
            file_id: Some(entry.file_id),
            metadata,
        }
    }

    fn read_object_directory(&mut self, path: &str, obj_id: u64) -> FsResult<Vec<FsEntry>> {
        let raw = self
            .volume
            .read_dir(&mut self.reader, obj_id)
            .map_err(|e| map_apfs_error(e, path))?;
        let parent = PathBuf::from(path);

        let mut entries = Vec::with_capacity(raw.len());
        for entry in raw {
            entries.push(self.entry_to_fs_entry(&parent, entry));
        }
        Ok(entries)
    }
}

impl<R: Read + Seek + Send> TargetFilesystem for ApfsFilesystem<R> {
    fn open(&mut self, path: &str) -> FsResult<OpenedTarget> {
        let metadata = self.metadata_at(path)?;
        if metadata.is_dir {
            let cached = self.resolved.take(path).ok_or_else(|| {
                FsError::Filesystem("APFS path cache was not populated".to_string())
            })?;
            Ok(OpenedTarget::directory(path, metadata, cached))
        } else {
            self.cache_regular_file(path)?;
            let cached = self.resolved.take(path).ok_or_else(|| {
                FsError::Filesystem("APFS file cache was not populated".to_string())
            })?;
            Ok(OpenedTarget::file(path, metadata, cached))
        }
    }

    fn read_open_file(
        &mut self,
        file: &mut OpenedFile,
        offset: u64,
        buffer: &mut [u8],
    ) -> FsResult<usize> {
        let path = file.path().to_string();
        let cached = file.context_mut::<CachedApfsTarget>().ok_or_else(|| {
            FsError::Filesystem("APFS received a foreign file handle".to_string())
        })?;
        let stream = cached
            .file
            .as_ref()
            .ok_or_else(|| FsError::Filesystem("APFS open file has no data stream".to_string()))?;
        stream
            .read_at(&mut self.reader, self.block_size, offset, buffer)
            .map_err(|error| map_apfs_error(error, &path))
    }

    fn load_open_directory(&mut self, directory: &mut OpenedDirectory) -> FsResult<Vec<FsEntry>> {
        let path = directory.path().to_string();
        let obj_id = directory
            .context_mut::<CachedApfsTarget>()
            .ok_or_else(|| {
                FsError::Filesystem("APFS received a foreign directory handle".to_string())
            })?
            .obj_id;
        self.read_object_directory(&path, obj_id)
    }

    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        self.cache_regular_file(path)?;
        self.resolved
            .get(path)
            .and_then(|cached| cached.file.as_ref())
            .ok_or_else(|| FsError::Filesystem("APFS file cache was not populated".to_string()))?
            .read_all(&mut self.reader, self.block_size)
            .map_err(|e| map_apfs_error(e, path))
    }

    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> FsResult<usize> {
        self.cache_regular_file(path)?;
        self.resolved
            .get(path)
            .and_then(|cached| cached.file.as_ref())
            .ok_or_else(|| FsError::Filesystem("APFS file cache was not populated".to_string()))?
            .read_at(&mut self.reader, self.block_size, offset, buffer)
            .map_err(|e| map_apfs_error(e, path))
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        found(self.navigate(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        match self.cache_inode(path) {
            Ok(()) => Ok(self
                .resolved
                .get(path)
                .and_then(|cached| cached.inode.as_ref())
                .is_some_and(Inode::is_directory)),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        match self.cache_inode(path) {
            Ok(()) => Ok(self
                .resolved
                .get(path)
                .and_then(|cached| cached.inode.as_ref())
                .is_some_and(|inode| inode.file_type() == FileType::Regular)),
            Err(FsError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        self.metadata_at(path)
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        self.cache_inode(path)?;
        let cached = self
            .resolved
            .get(path)
            .ok_or_else(|| FsError::Filesystem("APFS path cache was not populated".to_string()))?;
        if !cached.inode.as_ref().is_some_and(Inode::is_directory) {
            return Err(FsError::NotADirectory(path.to_string()));
        }
        let obj_id = cached.obj_id;
        self.read_object_directory(path, obj_id)
    }

    fn total_size(&self) -> Option<u64> {
        Some(self.total_size)
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(identity::uuid(&self.volume_uuid))
    }
}

/// [`FilesystemDriver`] for APFS containers.
///
/// Opens the container's Data-role volume, falling back to System and then
/// to the first volume. Use [`ApfsFilesystem::open`] directly to choose a
/// different volume.
pub struct ApfsDriver;

impl FilesystemDriver for ApfsDriver {
    fn name(&self) -> &'static str {
        "apfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Apfs
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(ApfsFilesystem::new(reader)?))
    }

    fn open_with_options(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        reject_unsupported_recovery(self.name(), options)?;
        Ok(Box::new(ApfsFilesystem::open(
            reader,
            &requested_volume(options.root())?,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// `ApfsSuperblock` has no public constructor, so the selector tests
    /// parse a synthetic block carrying just the fields they read.
    fn superblock(name: &str, role: VolumeRole) -> ApfsSuperblock {
        let mut block = vec![0u8; fs_apfs::volume::APFS_SUPERBLOCK_SIZE];
        block[0x18..0x1C].copy_from_slice(&0x0000_000Du32.to_le_bytes()); // FS object type
        block[0x20..0x24].copy_from_slice(&u32::from_le_bytes(*b"APSB").to_le_bytes());
        let name_bytes = name.as_bytes();
        block[0x2C0..0x2C0 + name_bytes.len()].copy_from_slice(name_bytes);
        block[0x3C4..0x3C6].copy_from_slice(&role_field(role).to_le_bytes());
        ApfsSuperblock::parse(&block).expect("synthetic volume superblock")
    }

    /// The `apfs_role` field value for the roles the tests use.
    fn role_field(role: VolumeRole) -> u16 {
        match role {
            VolumeRole::None => 0x0000,
            VolumeRole::System => 0x0001,
            VolumeRole::Data => 0x0040,
            other => panic!("unsupported test role {other:?}"),
        }
    }

    #[test]
    fn driver_supports_only_apfs() {
        crate::test_support::assert_supports_exactly(&ApfsDriver, &[DetectedBootSector::Apfs]);
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(ApfsDriver.name(), "apfs");
    }

    #[test]
    fn generic_root_selection_maps_to_apfs_volumes() {
        assert_eq!(
            requested_volume(&FilesystemRoot::Index(2)).expect("index"),
            VolumeSelector::Index(2)
        );
        assert_eq!(
            requested_volume(&FilesystemRoot::Name("Data".to_string())).expect("name"),
            VolumeSelector::Name("Data".to_string())
        );
        assert_eq!(
            requested_volume(&FilesystemRoot::Role("DATA".to_string())).expect("role"),
            VolumeSelector::Role(VolumeRole::Data)
        );
        assert!(requested_volume(&FilesystemRoot::Path("root".to_string())).is_err());
        assert!(requested_volume(&FilesystemRoot::Role("unknown".to_string())).is_err());
    }

    #[test]
    fn opening_a_non_apfs_image_fails() {
        let reader = Box::new(Cursor::new(vec![0u8; 8192]));
        assert!(
            ApfsDriver.open(reader, DetectedBootSector::Apfs).is_err(),
            "an all-zero image must not parse as an APFS container"
        );
    }

    #[test]
    fn auto_selector_prefers_the_data_volume() {
        let volumes = [
            superblock("System", VolumeRole::System),
            superblock("Data", VolumeRole::Data),
            superblock("Other", VolumeRole::None),
        ];
        assert_eq!(
            select_volume_index(&volumes, &VolumeSelector::Auto).expect("selection"),
            1
        );
    }

    #[test]
    fn auto_selector_falls_back_to_system_then_first() {
        let with_system = [
            superblock("Other", VolumeRole::None),
            superblock("System", VolumeRole::System),
        ];
        assert_eq!(
            select_volume_index(&with_system, &VolumeSelector::Auto).expect("selection"),
            1
        );

        let no_roles = [
            superblock("First", VolumeRole::None),
            superblock("Second", VolumeRole::None),
        ];
        assert_eq!(
            select_volume_index(&no_roles, &VolumeSelector::Auto).expect("selection"),
            0
        );
    }

    #[test]
    fn index_selector_validates_range() {
        let volumes = [superblock("Only", VolumeRole::Data)];
        assert_eq!(
            select_volume_index(&volumes, &VolumeSelector::Index(0)).expect("selection"),
            0
        );
        assert!(select_volume_index(&volumes, &VolumeSelector::Index(5)).is_err());
    }

    #[test]
    fn role_and_name_selectors_match_or_error() {
        let volumes = [
            superblock("Macintosh HD", VolumeRole::System),
            superblock("Macintosh HD - Data", VolumeRole::Data),
        ];
        assert_eq!(
            select_volume_index(&volumes, &VolumeSelector::Role(VolumeRole::Data))
                .expect("selection"),
            1
        );
        assert!(
            select_volume_index(&volumes, &VolumeSelector::Role(VolumeRole::Recovery)).is_err()
        );
        assert_eq!(
            select_volume_index(&volumes, &VolumeSelector::Name("Macintosh HD".to_string()))
                .expect("selection"),
            0
        );
        assert!(select_volume_index(&volumes, &VolumeSelector::Name("Nope".to_string())).is_err());
    }

    #[test]
    fn empty_container_is_rejected() {
        assert!(select_volume_index(&[], &VolumeSelector::Auto).is_err());
    }

    #[test]
    fn error_mapping_preserves_not_found() {
        assert!(matches!(
            map_apfs_error(
                ApfsError::NotFound {
                    what: "path component",
                },
                "/missing",
            ),
            FsError::NotFound(p) if p == "/missing"
        ));
        assert!(matches!(
            map_apfs_error(ApfsError::Unsupported("snapshots"), "/x"),
            FsError::Filesystem(_)
        ));
    }

    #[test]
    fn zero_timestamp_is_treated_as_unset() {
        assert!(ts_to_utc(ApfsTimestamp::from(0)).is_none());
        assert!(ts_to_utc(ApfsTimestamp::from(1_700_000_000_000_000_000)).is_some());
    }
}
