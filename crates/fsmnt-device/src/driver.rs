//! Plug-in interface for filesystem parsers.
//!
//! `fsmnt` contains no filesystem parsers of its own.  A consumer that
//! wants to mount raw partitions (NTFS, FAT, ext, APFS, …) implements
//! [`FilesystemDriver`] for each parser it provides — typically as a thin
//! adapter over an existing parser crate — and registers them in a
//! [`DriverRegistry`].

use fsmnt_core::{FsError, FsResult, TargetFilesystem};
use nostdio::{Read, Seek};

use crate::{DetectedBootSector, DeviceSet};

/// Combined reader bound required by filesystem drivers.
///
/// Blanket-implemented for every `Read + Seek + Send` type.
pub trait DeviceReader: Read + Seek + Send {}

impl<T: Read + Seek + Send + ?Sized> DeviceReader for T {}

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
            let available = if self.drivers.is_empty() {
                "none registered".to_string()
            } else {
                self.names().join(", ")
            };
            return Err(FsError::Filesystem(format!(
                "no filesystem driver for {detected:?} (available drivers: {available})"
            )));
        };
        driver.open(reader, detected)
    }

    /// Open a filesystem over one or more raw device members.
    ///
    /// # Errors
    ///
    /// Returns an error if no registered driver supports `detected`, if the
    /// selected driver rejects the supplied device set, or if parsing fails.
    pub fn open_devices(
        &self,
        devices: DeviceSet,
        detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let Some(driver) = self.find(detected) else {
            let available = if self.drivers.is_empty() {
                "none registered".to_string()
            } else {
                self.names().join(", ")
            };
            return Err(FsError::Filesystem(format!(
                "no filesystem driver for {detected:?} (available drivers: {available})"
            )));
        };
        driver.open_devices(devices, detected)
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
}
