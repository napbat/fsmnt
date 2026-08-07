//! Host drive enumeration abstraction.
//!
//! Provides a platform-agnostic interface for enumerating and accessing
//! physical drives on the host machine.  Platform crates implement
//! [`HostDriveEnumerator`]; consumers use it to discover what drives are
//! available for mounting.

use std::io::{Read, Seek};
use std::path::PathBuf;

use thiserror::Error;

/// Error type for host drive operations.
#[derive(Debug, Error)]
pub enum HostDriveError {
    /// Drive not found.
    #[error("Drive not found: {0}")]
    NotFound(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Access denied.
    #[error("Access denied (start fsmnt-proxy-server with elevated privileges)")]
    AccessDenied,

    /// Parse error.
    #[error("Parse error: {0}")]
    Parse(String),

    /// Platform not supported.
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

/// Result type for host drive operations.
pub type HostDriveResult<T> = Result<T, HostDriveError>;

/// Platform-agnostic drive identifier.
///
/// On Windows: `"0"`, `"1"`, … (`PhysicalDrive` index).
/// On Linux: `"sda"`, `"nvme0n1"`, ….
/// On macOS: `"disk0"`, `"disk2"`, ….
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostDriveId(pub String);

impl HostDriveId {
    /// Create a new drive ID from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HostDriveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Bus type for a physical drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDriveBusType {
    /// Unknown bus type.
    Unknown,
    /// SCSI.
    Scsi,
    /// ATAPI (IDE/PATA).
    Atapi,
    /// ATA (IDE/PATA).
    Ata,
    /// IEEE 1394 (`FireWire`).
    Ieee1394,
    /// SSA.
    Ssa,
    /// Fibre Channel.
    FibreChannel,
    /// USB.
    Usb,
    /// RAID.
    Raid,
    /// iSCSI.
    Iscsi,
    /// Serial Attached SCSI.
    Sas,
    /// SATA.
    Sata,
    /// SD card.
    Sd,
    /// MMC.
    Mmc,
    /// Virtual.
    Virtual,
    /// File-backed virtual.
    FileBackedVirtual,
    /// Storage Spaces.
    Spaces,
    /// `NVMe`.
    Nvme,
    /// SCM (Storage Class Memory).
    Scm,
    /// UFS (Universal Flash Storage).
    Ufs,
}

impl std::fmt::Display for HostDriveBusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Scsi => write!(f, "SCSI"),
            Self::Atapi => write!(f, "ATAPI"),
            Self::Ata => write!(f, "ATA"),
            Self::Ieee1394 => write!(f, "IEEE 1394"),
            Self::Ssa => write!(f, "SSA"),
            Self::FibreChannel => write!(f, "Fibre Channel"),
            Self::Usb => write!(f, "USB"),
            Self::Raid => write!(f, "RAID"),
            Self::Iscsi => write!(f, "iSCSI"),
            Self::Sas => write!(f, "SAS"),
            Self::Sata => write!(f, "SATA"),
            Self::Sd => write!(f, "SD"),
            Self::Mmc => write!(f, "MMC"),
            Self::Virtual => write!(f, "Virtual"),
            Self::FileBackedVirtual => write!(f, "File-backed Virtual"),
            Self::Spaces => write!(f, "Storage Spaces"),
            Self::Nvme => write!(f, "NVMe"),
            Self::Scm => write!(f, "SCM"),
            Self::Ufs => write!(f, "UFS"),
        }
    }
}

/// Information about a physical drive on the host.
#[derive(Debug, Clone)]
pub struct HostDriveInfo {
    /// Platform-agnostic drive identifier.
    pub id: HostDriveId,
    /// Full path to the drive device (e.g. `\\.\PhysicalDrive0` or
    /// `/dev/sda`).
    pub path: PathBuf,
    /// Total size in bytes (`None` if not accessible).
    pub size_bytes: Option<u64>,
    /// Logical sector size in bytes (typically 512 or 4096).
    pub sector_size: Option<u32>,
    /// Device model (if available).
    pub model: Option<String>,
    /// Device serial number (if available).
    pub serial_number: Option<String>,
    /// Bus type (SATA, `NVMe`, USB, …).
    pub bus_type: Option<HostDriveBusType>,
    /// Whether the drive has removable media.
    pub removable: Option<bool>,
    /// Whether we have read access to this drive.
    pub accessible: bool,
    /// Error message if access was denied or failed.
    pub access_error: Option<String>,
}

impl HostDriveInfo {
    /// Create a new [`HostDriveInfo`] with required fields.
    #[must_use]
    pub fn new(id: HostDriveId, path: PathBuf) -> Self {
        Self {
            id,
            path,
            size_bytes: None,
            sector_size: None,
            model: None,
            serial_number: None,
            bus_type: None,
            removable: None,
            accessible: false,
            access_error: None,
        }
    }

    /// Mark the drive as accessible with the given size.
    #[must_use]
    pub fn with_access(mut self, size_bytes: u64) -> Self {
        self.size_bytes = Some(size_bytes);
        self.accessible = true;
        self
    }

    /// Mark the drive as inaccessible with an error message.
    #[must_use]
    pub fn with_error(mut self, error: &str) -> Self {
        self.accessible = false;
        self.access_error = Some(error.to_string());
        self
    }

    /// Set the device model.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set the serial number.
    #[must_use]
    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.serial_number = Some(serial.into());
        self
    }

    /// Set the bus type.
    #[must_use]
    pub fn with_bus_type(mut self, bus_type: HostDriveBusType) -> Self {
        self.bus_type = Some(bus_type);
        self
    }

    /// Set whether the drive has removable media.
    #[must_use]
    pub fn with_removable(mut self, removable: bool) -> Self {
        self.removable = Some(removable);
        self
    }

    /// Set the size (for inaccessible drives where the size is still known,
    /// e.g. from sysfs).
    #[must_use]
    pub fn with_size(mut self, size_bytes: u64) -> Self {
        self.size_bytes = Some(size_bytes);
        self
    }

    /// Set the logical sector size in bytes.
    #[must_use]
    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = Some(sector_size);
        self
    }
}

/// Trait for platform-specific host drive enumeration.
///
/// Each platform crate implements this trait to provide drive enumeration
/// functionality specific to that operating system.
///
/// All open methods provide **read-only** access with platform-specific
/// flags to prevent kernel side-effects (e.g. automount on macOS).
pub trait HostDriveEnumerator {
    /// The reader type returned by [`open_drive`](Self::open_drive).
    type Reader: Read + Seek + Send + 'static;

    /// Enumerate all physical drives on the host.
    ///
    /// Returns info for all drives found, including those with access
    /// denied (with `accessible = false`).
    ///
    /// # Errors
    ///
    /// Returns an error if drive enumeration itself failed (individual
    /// inaccessible drives are not an error).
    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>>;

    /// Get information about a specific drive by ID.
    ///
    /// Returns info even if access is denied (with `accessible = false`).
    ///
    /// # Errors
    ///
    /// Returns an error if the drive does not exist or could not be
    /// queried.
    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo>;

    /// Open a drive for **read-only** raw access.
    ///
    /// # Errors
    ///
    /// Returns an error if the drive does not exist or cannot be opened
    /// (e.g. insufficient privileges).
    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader>;

    /// Try to open the operating system's volume for a partition.
    ///
    /// On Windows, this maps a physical drive and byte offset to the matching
    /// volume GUID. If that volume is encrypted and already unlocked, reads
    /// use the operating system's decrypted view.
    ///
    /// Returns `Ok(None)` on platforms that don't support this, or when no
    /// mounted volume matches the given extent.
    ///
    /// # Errors
    ///
    /// Returns an error if a matching volume is found but cannot be opened.
    fn open_volume_at(
        _drive_id: &HostDriveId,
        _offset: u64,
    ) -> HostDriveResult<Option<Self::Reader>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_drive_id_display() {
        let id = HostDriveId::new("sda");
        assert_eq!(id.to_string(), "sda");
        assert_eq!(id.as_str(), "sda");
    }

    #[test]
    fn host_drive_id_equality() {
        let a = HostDriveId::new("nvme0n1");
        let b = HostDriveId::new("nvme0n1");
        assert_eq!(a, b);
    }

    #[test]
    fn host_drive_info_new_defaults() {
        let info = HostDriveInfo::new(HostDriveId::new("0"), PathBuf::from("/dev/sda"));
        assert!(!info.accessible);
        assert!(info.size_bytes.is_none());
        assert!(info.model.is_none());
        assert!(info.serial_number.is_none());
        assert!(info.bus_type.is_none());
        assert!(info.access_error.is_none());
    }

    #[test]
    fn host_drive_info_builder_chain() {
        let info = HostDriveInfo::new(HostDriveId::new("0"), PathBuf::from("/dev/sda"))
            .with_access(500_000_000_000)
            .with_model("Samsung SSD 980")
            .with_serial("S123456")
            .with_bus_type(HostDriveBusType::Nvme)
            .with_removable(false)
            .with_sector_size(512);

        assert!(info.accessible);
        assert_eq!(info.size_bytes, Some(500_000_000_000));
        assert_eq!(info.model.as_deref(), Some("Samsung SSD 980"));
        assert_eq!(info.serial_number.as_deref(), Some("S123456"));
        assert_eq!(info.bus_type, Some(HostDriveBusType::Nvme));
        assert_eq!(info.removable, Some(false));
        assert_eq!(info.sector_size, Some(512));
    }

    #[test]
    fn host_drive_info_with_error() {
        let info = HostDriveInfo::new(HostDriveId::new("1"), PathBuf::from("/dev/sdb"))
            .with_error("access denied");

        assert!(!info.accessible);
        assert_eq!(info.access_error.as_deref(), Some("access denied"));
    }

    #[test]
    fn host_drive_error_display() {
        let err = HostDriveError::NotFound("sdc".into());
        assert!(err.to_string().contains("sdc"));

        let err = HostDriveError::AccessDenied;
        assert!(err.to_string().contains("elevated"));
    }

    #[test]
    fn host_drive_bus_type_display() {
        assert_eq!(HostDriveBusType::Nvme.to_string(), "NVMe");
        assert_eq!(HostDriveBusType::Sata.to_string(), "SATA");
        assert_eq!(HostDriveBusType::Usb.to_string(), "USB");
        assert_eq!(HostDriveBusType::Unknown.to_string(), "Unknown");
    }
}
