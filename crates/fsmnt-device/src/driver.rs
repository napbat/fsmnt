//! Plug-in interface for filesystem parsers.
//!
//! `fsmnt` contains no filesystem parsers of its own.  A consumer that
//! wants to mount raw partitions (NTFS, FAT, ext, APFS, …) implements
//! [`FilesystemDriver`] for each parser it provides — typically as a thin
//! adapter over an existing parser crate — and registers them in a
//! [`DriverRegistry`].

use fsmnt_core::{FsError, FsResult, TargetFilesystem};
use nostdio::{Read, Seek};
use std::fmt;
use std::str::FromStr;

use crate::{DetectedBootSector, DeviceMember, DeviceSet};

/// Combined reader bound required by filesystem drivers.
///
/// Blanket-implemented for every `Read + Seek + Send` type.
pub trait DeviceReader: Read + Seek + Send {}

impl<T: Read + Seek + Send + ?Sized> DeviceReader for T {}

/// Filesystem-owned tree or volume to expose as the mounted root.
///
/// Drivers interpret the selectors they support and reject incompatible
/// selectors explicitly. This layer is distinct from [`SourceSelection`]:
/// source selection chooses an operating-system or physical block view,
/// while this type chooses a root inside the opened filesystem/container.
///
/// [`SourceSelection`]: crate::SourceSelection
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum FilesystemRoot {
    /// Use the filesystem driver's normal default root.
    #[default]
    Default,
    /// Use the filesystem's top-level tree rather than a configured child.
    TopLevel,
    /// Select a filesystem-owned root by a hierarchy path.
    Path(String),
    /// Select a filesystem-owned root by numeric identifier.
    Id(u64),
    /// Select a container volume by its zero-based index.
    Index(usize),
    /// Select a container volume by its exact name.
    Name(String),
    /// Select a container volume by its semantic role.
    Role(String),
}

impl fmt::Display for FilesystemRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("default"),
            Self::TopLevel => formatter.write_str("top-level"),
            Self::Path(path) => write!(formatter, "path:{path}"),
            Self::Id(id) => write!(formatter, "id:{id}"),
            Self::Index(index) => write!(formatter, "index:{index}"),
            Self::Name(name) => write!(formatter, "name:{name}"),
            Self::Role(role) => write!(formatter, "role:{role}"),
        }
    }
}

/// Failure to parse a textual [`FilesystemRoot`] selector.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "invalid filesystem root selector {value:?}: expected default, top-level, \
     path:PATH, id:NUMBER, index:NUMBER, name:NAME, or role:ROLE"
)]
pub struct FilesystemRootParseError {
    value: String,
}

impl FromStr for FilesystemRoot {
    type Err = FilesystemRootParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "default" => return Ok(Self::Default),
            "top-level" => return Ok(Self::TopLevel),
            _ => {}
        }
        let (kind, payload) = value
            .split_once(':')
            .filter(|(_, payload)| !payload.is_empty())
            .ok_or_else(|| invalid_root_selector(value))?;
        match kind {
            "path" => Ok(Self::Path(payload.to_string())),
            "id" => payload
                .parse()
                .map(Self::Id)
                .map_err(|_| invalid_root_selector(value)),
            "index" => payload
                .parse()
                .map(Self::Index)
                .map_err(|_| invalid_root_selector(value)),
            "name" => Ok(Self::Name(payload.to_string())),
            "role" => Ok(Self::Role(payload.to_string())),
            _ => Err(invalid_root_selector(value)),
        }
    }
}

fn invalid_root_selector(value: &str) -> FilesystemRootParseError {
    FilesystemRootParseError {
        value: value.to_string(),
    }
}

/// Options applied while a filesystem driver opens its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemOpenOptions {
    root: FilesystemRoot,
    journal_replay: bool,
}

impl FilesystemOpenOptions {
    /// Create options using the driver's default filesystem root, with
    /// journal replay enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: FilesystemRoot::Default,
            journal_replay: true,
        }
    }

    /// Select the filesystem-owned root to expose.
    #[must_use]
    pub fn with_root(mut self, root: FilesystemRoot) -> Self {
        self.root = root;
        self
    }

    /// Whether a driver may replay a dirty journal (and orphan lists) into
    /// an in-memory overlay before serving reads.
    ///
    /// Replay never writes to the source: fsmnt reads are read-only
    /// regardless of this setting. It only decides which *view* a dirty
    /// volume presents — the recovered state (default), or the bytes exactly
    /// as they sit on disk (`false`), which is what evidence-handling
    /// workflows compare against carving results. Drivers without journal
    /// replay satisfy `false` trivially.
    #[must_use]
    pub const fn with_journal_replay(mut self, replay: bool) -> Self {
        self.journal_replay = replay;
        self
    }

    /// Requested filesystem-owned root.
    #[must_use]
    pub const fn root(&self) -> &FilesystemRoot {
        &self.root
    }

    /// Whether journal replay into an overlay is permitted.
    #[must_use]
    pub const fn journal_replay(&self) -> bool {
        self.journal_replay
    }
}

impl Default for FilesystemOpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Filesystem opened after any geometry-dependent driver probe.
pub struct ResolvedFilesystem {
    /// Opened mountable filesystem.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// Format selected by the winning driver.
    pub detected: DetectedBootSector,
}

/// Opaque identity of one member in a filesystem-owned multi-device layout.
///
/// The bytes are interpreted only by the driver that produced them. The
/// device layer uses equality to match discovered partitions without learning
/// filesystem-specific on-disk structures.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilesystemMemberId(Vec<u8>);

impl FilesystemMemberId {
    /// Wrap a stable driver-defined member identity.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Driver-defined identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Member information obtained from filesystem-owned metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemMemberDiscovery {
    member: FilesystemMemberId,
    required: Vec<FilesystemMemberId>,
    detected: DetectedBootSector,
}

impl FilesystemMemberDiscovery {
    /// Create a discovery result and normalize its required-member set.
    #[must_use]
    pub fn new(
        detected: DetectedBootSector,
        member: FilesystemMemberId,
        mut required: Vec<FilesystemMemberId>,
    ) -> Self {
        if !required.contains(&member) {
            required.push(member.clone());
        }
        required.sort_unstable();
        required.dedup();
        Self {
            member,
            required,
            detected,
        }
    }

    /// Filesystem format resolved by the driver.
    #[must_use]
    pub const fn detected(&self) -> DetectedBootSector {
        self.detected
    }

    /// Identity of the member that was inspected.
    #[must_use]
    pub const fn member(&self) -> &FilesystemMemberId {
        &self.member
    }

    /// Every member referenced by authoritative filesystem metadata.
    #[must_use]
    pub fn required_members(&self) -> &[FilesystemMemberId] {
        &self.required
    }

    /// Whether `candidate` is referenced by this filesystem.
    #[must_use]
    pub fn requires(&self, candidate: &FilesystemMemberId) -> bool {
        self.required.contains(candidate)
    }
}

/// Driver-qualified member discovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMemberDiscovery {
    driver_name: &'static str,
    discovery: FilesystemMemberDiscovery,
}

impl ResolvedMemberDiscovery {
    /// Driver that interpreted the member metadata.
    #[must_use]
    pub const fn driver_name(&self) -> &'static str {
        self.driver_name
    }

    /// Filesystem-owned discovery details.
    #[must_use]
    pub const fn discovery(&self) -> &FilesystemMemberDiscovery {
        &self.discovery
    }
}

/// Opens a [`TargetFilesystem`] over a raw partition reader.
///
/// The reader passed to [`open`](Self::open) is scoped to the partition
/// (offset 0 = start of the partition), typically a
/// [`PartitionReader`](crate::PartitionReader) over a block device or
/// image file.
pub trait FilesystemDriver: Send + Sync {
    /// Short identifier for this driver (e.g. `"ntfs"`).
    fn name(&self) -> &'static str;

    /// Whether this driver can open a partition of the given detected type.
    fn supports(&self, detected: DetectedBootSector) -> bool;

    /// Probe a device set when boot-sector detection alone is insufficient.
    ///
    /// The default implementation delegates to [`supports`](Self::supports)
    /// without reading. Drivers for layouts whose identifying metadata moves
    /// with device geometry can override this method. An override must restore
    /// every reader position before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when authoritative source geometry or probe bytes
    /// cannot be read.
    fn probe_devices(
        &self,
        _devices: &mut DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Option<DetectedBootSector>> {
        Ok(self.supports(detected).then_some(detected))
    }

    /// Inspect one raw member for filesystem-owned multi-device identities.
    ///
    /// Drivers that own device mapping, such as Btrfs, return the inspected
    /// member identity and every member referenced by authoritative metadata.
    /// Other drivers return `None`. Implementations must restore the reader
    /// position before returning, including on errors.
    ///
    /// # Errors
    ///
    /// Returns an error when a positively identified filesystem has malformed
    /// member metadata or the original reader position cannot be restored.
    fn discover_members(
        &self,
        _member: &mut DeviceMember,
        _detected: DetectedBootSector,
    ) -> FsResult<Option<FilesystemMemberDiscovery>> {
        Ok(None)
    }

    /// Open a filesystem over `reader`.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition cannot be parsed as this driver's
    /// filesystem type.
    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>>;

    /// Open a filesystem with explicit open options.
    ///
    /// The default implementation accepts only [`FilesystemRoot::Default`]
    /// and delegates to [`open`](Self::open). It ignores
    /// [`FilesystemOpenOptions::journal_replay`]: a driver that never
    /// replays a journal already presents the on-disk state, so declining
    /// replay changes nothing. Drivers that do replay (ext) override this
    /// method to honour it.
    ///
    /// # Errors
    ///
    /// Returns an error when this driver does not support the requested root
    /// selector or opening fails.
    fn open_with_options(
        &self,
        reader: Box<dyn DeviceReader>,
        detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        if options.root() != &FilesystemRoot::Default {
            return Err(unsupported_root(self.name(), options.root()));
        }
        self.open(reader, detected)
    }

    /// Open a filesystem from one or more raw device members.
    ///
    /// The default implementation accepts one member and delegates to
    /// [`open`](Self::open). Filesystem drivers with native multi-device
    /// layouts override this method and consume the complete set.
    ///
    /// # Errors
    ///
    /// Returns an error when several members are supplied to a driver that
    /// only implements single-device opening, or when opening fails.
    fn open_devices(
        &self,
        devices: DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let reader = devices
            .into_single_reader()
            .map_err(|error| FsError::Filesystem(error.to_string()))?;
        self.open(reader, detected)
    }

    /// Open one or more raw members with filesystem-open options.
    ///
    /// The default implementation delegates all-default requests to
    /// [`open_devices`](Self::open_devices). For any explicit option (a
    /// root selector, journal replay disabled) it accepts one member and
    /// delegates to [`open_with_options`](Self::open_with_options).
    ///
    /// # Errors
    ///
    /// Returns an error when the device set or requested root is unsupported,
    /// or opening fails.
    fn open_devices_with_options(
        &self,
        devices: DeviceSet,
        detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        if options == &FilesystemOpenOptions::new() {
            return self.open_devices(devices, detected);
        }
        let reader = devices
            .into_single_reader()
            .map_err(|error| FsError::Filesystem(error.to_string()))?;
        self.open_with_options(reader, detected, options)
    }
}

fn unsupported_root(driver: &str, root: &FilesystemRoot) -> FsError {
    FsError::Filesystem(format!(
        "filesystem driver {driver:?} does not support root selector {root:?}"
    ))
}

/// An ordered collection of [`FilesystemDriver`]s.
///
/// Drivers are consulted in registration order; the first driver that
/// [`supports`](FilesystemDriver::supports) a detected type wins.
#[derive(Default)]
pub struct DriverRegistry {
    drivers: Vec<Box<dyn FilesystemDriver>>,
}

impl DriverRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a driver.  Drivers are tried in registration order.
    pub fn register(&mut self, driver: Box<dyn FilesystemDriver>) {
        self.drivers.push(driver);
    }

    /// Returns `true` if no drivers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }

    /// The names of all registered drivers, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.drivers.iter().map(|d| d.name()).collect()
    }

    /// Find the first registered driver that supports `detected`.
    #[must_use]
    pub fn find(&self, detected: DetectedBootSector) -> Option<&dyn FilesystemDriver> {
        self.drivers
            .iter()
            .find(|d| d.supports(detected))
            .map(AsRef::as_ref)
    }

    /// Open a filesystem over `reader` using the first driver that
    /// supports `detected`.
    ///
    /// # Errors
    ///
    /// Returns an error if no registered driver supports `detected`, or if
    /// the selected driver fails to open the partition.
    pub fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let Some(driver) = self.find(detected) else {
            return Err(self.no_driver_error(detected));
        };
        driver.open(reader, detected)
    }

    /// Open a filesystem using explicit filesystem-owned root options.
    ///
    /// # Errors
    ///
    /// Returns an error if no driver supports `detected`, the selected driver
    /// rejects the requested root, or opening fails.
    pub fn open_with_options(
        &self,
        reader: Box<dyn DeviceReader>,
        detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let Some(driver) = self.find(detected) else {
            return Err(self.no_driver_error(detected));
        };
        driver.open_with_options(reader, detected, options)
    }

    /// Open a filesystem over one or more raw device members.
    ///
    /// # Errors
    ///
    /// Returns an error if no registered driver supports `detected`, if the
    /// selected driver rejects the supplied device set, or if parsing fails.
    pub fn open_devices(
        &self,
        mut devices: DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let Some((driver, resolved)) = self.find_for_devices(&mut devices, detected)? else {
            return Err(self.no_driver_error(detected));
        };
        driver.open_devices(devices, resolved)
    }

    /// Open one or more raw members using filesystem-owned root options.
    ///
    /// # Errors
    ///
    /// Returns an error if no driver supports `detected`, the selected driver
    /// rejects the requested root or device set, or opening fails.
    pub fn open_devices_with_options(
        &self,
        devices: DeviceSet,
        detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        self.open_devices_with_options_resolved(devices, detected, options)
            .map(|opened| opened.filesystem)
    }

    /// Open device members and preserve the format selected by a
    /// geometry-dependent driver probe.
    ///
    /// # Errors
    ///
    /// Returns an error if probing fails, no driver recognizes the source, or
    /// the selected driver cannot open the requested filesystem root.
    pub fn open_devices_with_options_resolved(
        &self,
        mut devices: DeviceSet,
        detected: DetectedBootSector,
        options: &FilesystemOpenOptions,
    ) -> FsResult<ResolvedFilesystem> {
        let Some((driver, resolved)) = self.find_for_devices(&mut devices, detected)? else {
            return Err(self.no_driver_error(detected));
        };
        let filesystem = driver.open_devices_with_options(devices, resolved, options)?;
        Ok(ResolvedFilesystem {
            filesystem,
            detected: resolved,
        })
    }

    /// Ask registered drivers for filesystem-owned member identities.
    ///
    /// Drivers are consulted in registration order. A driver must return
    /// `None` without error when the member is not its format.
    ///
    /// # Errors
    ///
    /// Returns an error when a driver positively identifies the member but
    /// cannot parse its authoritative discovery metadata.
    pub fn discover_members(
        &self,
        member: &mut DeviceMember,
        detected: DetectedBootSector,
    ) -> FsResult<Option<ResolvedMemberDiscovery>> {
        for driver in &self.drivers {
            if let Some(discovery) = driver.discover_members(member, detected)? {
                return Ok(Some(ResolvedMemberDiscovery {
                    driver_name: driver.name(),
                    discovery,
                }));
            }
        }
        Ok(None)
    }

    fn find_for_devices<'a>(
        &'a self,
        devices: &mut DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Option<(&'a dyn FilesystemDriver, DetectedBootSector)>> {
        for driver in &self.drivers {
            if let Some(resolved) = driver.probe_devices(devices, detected)? {
                return Ok(Some((driver.as_ref(), resolved)));
            }
        }
        Ok(None)
    }

    fn no_driver_error(&self, detected: DetectedBootSector) -> FsError {
        let available = if self.drivers.is_empty() {
            "none registered".to_string()
        } else {
            self.names().join(", ")
        };
        FsError::Filesystem(format!(
            "no filesystem driver for {detected:?} (available drivers: {available})"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_core::{FsEntry, FsMetadata};

    struct NullFs;

    impl TargetFilesystem for NullFs {
        fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
            Err(FsError::NotFound(path.to_string()))
        }
        fn try_exists(&mut self, _path: &str) -> FsResult<bool> {
            Ok(false)
        }
        fn try_is_dir(&mut self, _path: &str) -> FsResult<bool> {
            Ok(false)
        }
        fn try_is_file(&mut self, _path: &str) -> FsResult<bool> {
            Ok(false)
        }
        fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
            Err(FsError::NotFound(path.to_string()))
        }
        fn read_dir(&mut self, _path: &str) -> FsResult<Vec<FsEntry>> {
            Ok(Vec::new())
        }
    }

    struct NullDriver;

    impl FilesystemDriver for NullDriver {
        fn name(&self) -> &'static str {
            "null"
        }
        fn supports(&self, detected: DetectedBootSector) -> bool {
            detected == DetectedBootSector::Ntfs
        }
        fn open(
            &self,
            _reader: Box<dyn DeviceReader>,
            _detected: DetectedBootSector,
        ) -> FsResult<Box<dyn TargetFilesystem>> {
            Ok(Box::new(NullFs))
        }
    }

    struct ProbeDriver;

    impl FilesystemDriver for ProbeDriver {
        fn name(&self) -> &'static str {
            "probe"
        }

        fn supports(&self, _detected: DetectedBootSector) -> bool {
            false
        }

        fn probe_devices(
            &self,
            _devices: &mut DeviceSet,
            detected: DetectedBootSector,
        ) -> FsResult<Option<DetectedBootSector>> {
            Ok((detected == DetectedBootSector::Unknown).then_some(DetectedBootSector::Ntfs))
        }

        fn open(
            &self,
            _reader: Box<dyn DeviceReader>,
            _detected: DetectedBootSector,
        ) -> FsResult<Box<dyn TargetFilesystem>> {
            Ok(Box::new(NullFs))
        }
    }

    #[test]
    fn empty_registry_reports_no_driver() {
        let registry = DriverRegistry::new();
        let reader = Box::new(std::io::Cursor::new(vec![0u8; 512]));
        let Err(err) = registry.open(reader, DetectedBootSector::Ntfs) else {
            panic!("expected error from empty registry");
        };
        assert!(err.to_string().contains("none registered"));
    }

    #[test]
    fn finds_supporting_driver() {
        let mut registry = DriverRegistry::new();
        registry.register(Box::new(NullDriver));

        assert!(registry.find(DetectedBootSector::Ntfs).is_some());
        assert!(registry.find(DetectedBootSector::Ext).is_none());
        assert_eq!(registry.names(), ["null"]);

        let reader = Box::new(std::io::Cursor::new(vec![0u8; 512]));
        assert!(registry.open(reader, DetectedBootSector::Ntfs).is_ok());
    }

    #[test]
    fn device_geometry_probe_can_select_an_unknown_format() {
        let mut registry = DriverRegistry::new();
        registry.register(Box::new(ProbeDriver));
        let member = crate::DeviceMember::new(
            crate::SourceMemberId::Synthetic("probe".to_string()),
            Box::new(std::io::Cursor::new(vec![0_u8; 512])),
            512,
            512,
        )
        .expect("device member");
        assert!(
            registry
                .open_devices(crate::DeviceSet::new(member), DetectedBootSector::Unknown)
                .is_ok()
        );
    }

    #[test]
    fn filesystem_root_specs_round_trip() {
        for root in [
            FilesystemRoot::Default,
            FilesystemRoot::TopLevel,
            FilesystemRoot::Path("root/snapshot:1".to_string()),
            FilesystemRoot::Id(256),
            FilesystemRoot::Index(2),
            FilesystemRoot::Name("Macintosh HD - Data".to_string()),
            FilesystemRoot::Role("data".to_string()),
        ] {
            assert_eq!(
                root.to_string().parse::<FilesystemRoot>(),
                Ok(root),
                "selector should round-trip"
            );
        }
    }

    #[test]
    fn malformed_filesystem_root_specs_are_rejected() {
        for value in [
            "",
            "root",
            "path:",
            "id:",
            "id:not-a-number",
            "index:-1",
            "role:",
            "unknown:value",
        ] {
            assert!(
                value.parse::<FilesystemRoot>().is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn default_driver_contract_rejects_explicit_roots() {
        let mut registry = DriverRegistry::new();
        registry.register(Box::new(NullDriver));
        let reader = Box::new(std::io::Cursor::new(vec![0_u8; 512]));
        let options =
            FilesystemOpenOptions::new().with_root(FilesystemRoot::Path("child".to_string()));
        let Err(error) = registry.open_with_options(reader, DetectedBootSector::Ntfs, &options)
        else {
            panic!("null driver has no root-selection support");
        };
        assert!(error.to_string().contains("root selector"));
    }

    #[test]
    fn member_discovery_includes_the_inspected_member_and_deduplicates() {
        let inspected = FilesystemMemberId::new(b"member-b".to_vec());
        let member_a = FilesystemMemberId::new(b"member-a".to_vec());
        let discovery = FilesystemMemberDiscovery::new(
            DetectedBootSector::Btrfs,
            inspected.clone(),
            vec![member_a.clone(), inspected.clone(), member_a.clone()],
        );

        assert_eq!(discovery.member(), &inspected);
        assert_eq!(discovery.required_members(), &[member_a, inspected]);
        assert!(discovery.requires(discovery.member()));
    }
}
