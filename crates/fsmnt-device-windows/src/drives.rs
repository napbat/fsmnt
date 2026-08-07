//! Windows physical-drive enumeration and raw read-only access.
//!
//! Enumerates physical drives (`\\.\PhysicalDrive<N>`) by probing device
//! paths, queries their size, sector size, and identity via
//! `DeviceIoControl`, and opens them for raw read-only access suitable for
//! partition-table and filesystem parsing.
//!
//! This module implements the
//! [`HostDriveEnumerator`](fsmnt_device::HostDriveEnumerator) trait for
//! Windows.

use std::ffi::c_void;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use fsmnt_device::{
    HostDriveBusType, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo,
    HostDriveResult,
};
use fsmnt_proxy::{OpenMode, open_with_proxy_fallback};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    DISK_GEOMETRY, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DRIVE_GEOMETRY,
    IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
};

use crate::volumes;

/// Maximum number of physical drives to probe during enumeration.
const MAX_PHYSICAL_DRIVES: u32 = 16;

/// Size of the output buffer for `IOCTL_STORAGE_QUERY_PROPERTY`.
const PROPERTY_BUFFER_LEN: usize = 1024;

/// Byte offset of `RemovableMedia` within `STORAGE_DEVICE_DESCRIPTOR`.
const SDD_REMOVABLE_MEDIA: usize = 10;
/// Byte offset of `VendorIdOffset` within `STORAGE_DEVICE_DESCRIPTOR`.
const SDD_VENDOR_ID_OFFSET: usize = 12;
/// Byte offset of `ProductIdOffset` within `STORAGE_DEVICE_DESCRIPTOR`.
const SDD_PRODUCT_ID_OFFSET: usize = 16;
/// Byte offset of `SerialNumberOffset` within `STORAGE_DEVICE_DESCRIPTOR`.
const SDD_SERIAL_NUMBER_OFFSET: usize = 24;
/// Byte offset of `BusType` within `STORAGE_DEVICE_DESCRIPTOR`.
const SDD_BUS_TYPE: usize = 28;

/// Windows host drive enumerator.
///
/// Implements the [`HostDriveEnumerator`] trait for Windows systems.
/// Drive IDs are numeric strings (`"0"`, `"1"`, `"2"`, ...) corresponding
/// to `\\.\PhysicalDrive0`, `\\.\PhysicalDrive1`, etc.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsHostDrives;

impl WindowsHostDrives {
    /// Open a raw volume by drive letter for **read-only** access
    /// (e.g. `"C"` or `"C:"`).
    ///
    /// This is a Windows-specific convenience method not part of the
    /// trait.  Reading through the mounted volume (rather than the raw
    /// physical drive) yields OS-decrypted data for volumes such as
    /// unlocked `BitLocker` partitions.
    ///
    /// # Errors
    ///
    /// Returns an error if `letter` is not a single ASCII drive letter,
    /// the volume does not exist, or it cannot be opened (e.g.
    /// insufficient privileges and no privileged proxy is available).
    pub fn open_raw_volume(letter: &str) -> HostDriveResult<BufReader<File>> {
        let letter = letter
            .trim_end_matches([':', '\\', '/'])
            .chars()
            .next()
            .ok_or_else(|| HostDriveError::NotFound(letter.to_string()))?;

        if !letter.is_ascii_alphabetic() {
            return Err(HostDriveError::NotFound(letter.to_string()));
        }

        let letter = letter.to_ascii_uppercase();
        let path = format!("\\\\.\\{letter}:");
        Ok(BufReader::new(open_device(&path)?))
    }
}

impl HostDriveEnumerator for WindowsHostDrives {
    type Reader = BufReader<File>;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        let mut drives = Vec::new();

        for i in 0..MAX_PHYSICAL_DRIVES {
            let id = HostDriveId::new(i.to_string());
            match query_drive_info(&id) {
                Ok(info) => drives.push(info),
                Err(HostDriveError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(drives)
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        query_drive_info(id)
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        let path = physical_drive_path(id)?;
        Ok(BufReader::new(open_device(&path)?))
    }

    fn open_volume_at(drive_id: &HostDriveId, offset: u64) -> Option<Self::Reader> {
        let disk_number: u32 = drive_id.as_str().parse().ok()?;
        let vol = volumes::find_volume_for_extent(disk_number, offset)?;
        let letter = vol.drive_letter()?;
        Self::open_raw_volume(letter).ok()
    }
}

/// Resolve a drive ID to its `\\.\PhysicalDrive<N>` device path.
fn physical_drive_path(id: &HostDriveId) -> HostDriveResult<String> {
    let index: u32 = id
        .as_str()
        .parse()
        .map_err(|_| HostDriveError::NotFound(id.to_string()))?;

    Ok(format!("\\\\.\\PhysicalDrive{index}"))
}

/// Open a device path for read-only access.
///
/// Tries a direct open first and, on access denial, asks the
/// `fsmnt-proxy-server` at its default endpoint for a duplicated read-only
/// handle.
fn open_device(path: &str) -> HostDriveResult<File> {
    open_with_proxy_fallback(path, OpenMode::ReadOnly, 0).map_err(|error| {
        if error.kind() == ErrorKind::PermissionDenied {
            HostDriveError::AccessDenied
        } else if error.kind() == ErrorKind::NotFound {
            HostDriveError::NotFound(path.to_string())
        } else {
            HostDriveError::Io(error)
        }
    })
}

/// Query drive info for one physical drive, reporting inaccessible drives
/// as `Ok` with `accessible = false` rather than as errors.
fn query_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
    let path_str = physical_drive_path(id)?;
    let path = PathBuf::from(&path_str);

    match open_device(&path_str) {
        Ok(file) => {
            let size = get_disk_size(&file).unwrap_or(0);
            let mut info = HostDriveInfo::new(id.clone(), path).with_access(size);

            if let Some(sector_size) = get_disk_sector_size(&file) {
                info = info.with_sector_size(sector_size);
            }

            if let Some(props) = get_disk_properties(&file) {
                if let Some(model) = props.model {
                    info = info.with_model(model);
                }
                if let Some(serial) = props.serial_number {
                    info = info.with_serial(serial);
                }
                if let Some(bus_type) = props.bus_type {
                    info = info.with_bus_type(bus_type);
                }
                info = info.with_removable(props.removable);
            }

            Ok(info)
        }
        Err(HostDriveError::AccessDenied) => Ok(HostDriveInfo::new(id.clone(), path)
            .with_error("Access denied (start fsmnt-proxy-server as Administrator)")),
        Err(HostDriveError::Io(ref e)) if e.kind() != ErrorKind::NotFound => {
            Ok(HostDriveInfo::new(id.clone(), path).with_error(&format!("I/O error: {e}")))
        }
        Err(e) => Err(e),
    }
}

/// Get the size of a disk in bytes using `IOCTL_DISK_GET_LENGTH_INFO`.
fn get_disk_size(file: &File) -> Option<u64> {
    let mut length_info = GET_LENGTH_INFORMATION::default();
    let mut bytes_returned: u32 = 0;

    let handle = HANDLE(file.as_raw_handle());

    // SAFETY: `handle` is a valid disk handle owned by `file` for the
    // duration of the call.  The output pointer refers to a live
    // `GET_LENGTH_INFORMATION` whose size matches the length argument, and
    // `bytes_returned` is a valid out pointer.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            Some(std::ptr::from_mut(&mut length_info).cast::<c_void>()),
            ioctl_len(size_of::<GET_LENGTH_INFORMATION>()),
            Some(&raw mut bytes_returned),
            None,
        )
    };

    if result.is_ok() {
        u64::try_from(length_info.Length).ok()
    } else {
        None
    }
}

/// Get the logical sector size of a disk using
/// `IOCTL_DISK_GET_DRIVE_GEOMETRY`.
fn get_disk_sector_size(file: &File) -> Option<u32> {
    let mut geometry = DISK_GEOMETRY::default();
    let mut bytes_returned: u32 = 0;

    let handle = HANDLE(file.as_raw_handle());

    // SAFETY: `handle` is a valid disk handle owned by `file` for the
    // duration of the call.  The output pointer refers to a live
    // `DISK_GEOMETRY` whose size matches the length argument, and
    // `bytes_returned` is a valid out pointer.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None,
            0,
            Some(std::ptr::from_mut(&mut geometry).cast::<c_void>()),
            ioctl_len(size_of::<DISK_GEOMETRY>()),
            Some(&raw mut bytes_returned),
            None,
        )
    };

    if result.is_ok() && geometry.BytesPerSector > 0 {
        Some(geometry.BytesPerSector)
    } else {
        None
    }
}

/// Identity properties retrieved via `IOCTL_STORAGE_QUERY_PROPERTY`.
struct DiskProperties {
    /// Device model (vendor + product), if reported.
    model: Option<String>,
    /// Device serial number, if reported.
    serial_number: Option<String>,
    /// Bus type, if the reported value is recognized.
    bus_type: Option<HostDriveBusType>,
    /// Whether the device reports removable media.
    removable: bool,
}

/// Get disk identity properties using `IOCTL_STORAGE_QUERY_PROPERTY`.
fn get_disk_properties(file: &File) -> Option<DiskProperties> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };

    let mut buffer = [0u8; PROPERTY_BUFFER_LEN];
    let mut bytes_returned: u32 = 0;

    let handle = HANDLE(file.as_raw_handle());

    // SAFETY: `handle` is a valid disk handle owned by `file` for the
    // duration of the call.  The input pointer refers to `query` (live
    // across the call) with a matching length; the output pointer/length
    // describe `buffer`, and `bytes_returned` is a valid out pointer.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(std::ptr::from_ref(&query).cast::<c_void>()),
            ioctl_len(size_of::<STORAGE_PROPERTY_QUERY>()),
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            ioctl_len(buffer.len()),
            Some(&raw mut bytes_returned),
            None,
        )
    };
    result.ok()?;

    // Parse the `STORAGE_DEVICE_DESCRIPTOR` fields straight from the byte
    // buffer.  The descriptor is variable-length and the buffer is only
    // byte-aligned, so reading through a `#[repr(C)]` struct pointer would
    // be an unaligned (undefined-behavior) read.
    let removable = *buffer.get(SDD_REMOVABLE_MEDIA)? != 0;
    let vendor_offset = read_u32_le(&buffer, SDD_VENDOR_ID_OFFSET)?;
    let product_offset = read_u32_le(&buffer, SDD_PRODUCT_ID_OFFSET)?;
    let serial_offset = read_u32_le(&buffer, SDD_SERIAL_NUMBER_OFFSET)?;
    let bus_type_raw = read_u32_le(&buffer, SDD_BUS_TYPE)?;

    // Build the model string from vendor + product.
    let mut model_parts = Vec::new();
    if let Some(vendor) = string_at_offset(&buffer, vendor_offset) {
        model_parts.push(vendor);
    }
    if let Some(product) = string_at_offset(&buffer, product_offset) {
        model_parts.push(product);
    }
    let model = if model_parts.is_empty() {
        None
    } else {
        Some(model_parts.join(" "))
    };

    Some(DiskProperties {
        model,
        serial_number: string_at_offset(&buffer, serial_offset),
        bus_type: bus_type_from_raw(bus_type_raw),
        removable,
    })
}

/// Map a raw `STORAGE_BUS_TYPE` value to [`HostDriveBusType`].
fn bus_type_from_raw(raw: u32) -> Option<HostDriveBusType> {
    match raw {
        0 => Some(HostDriveBusType::Unknown),
        1 => Some(HostDriveBusType::Scsi),
        2 => Some(HostDriveBusType::Atapi),
        3 => Some(HostDriveBusType::Ata),
        4 => Some(HostDriveBusType::Ieee1394),
        5 => Some(HostDriveBusType::Ssa),
        6 => Some(HostDriveBusType::FibreChannel),
        7 => Some(HostDriveBusType::Usb),
        8 => Some(HostDriveBusType::Raid),
        9 => Some(HostDriveBusType::Iscsi),
        10 => Some(HostDriveBusType::Sas),
        11 => Some(HostDriveBusType::Sata),
        12 => Some(HostDriveBusType::Sd),
        13 => Some(HostDriveBusType::Mmc),
        14 => Some(HostDriveBusType::Virtual),
        15 => Some(HostDriveBusType::FileBackedVirtual),
        16 => Some(HostDriveBusType::Spaces),
        17 => Some(HostDriveBusType::Nvme),
        18 => Some(HostDriveBusType::Scm),
        19 => Some(HostDriveBusType::Ufs),
        _ => None,
    }
}

/// Extract a descriptor string at a `STORAGE_DEVICE_DESCRIPTOR` field
/// offset.  An offset of `0` means "not present".
fn string_at_offset(buffer: &[u8], offset: u32) -> Option<String> {
    if offset == 0 {
        return None;
    }
    extract_string(buffer, usize::try_from(offset).ok()?)
}

/// Extract a NUL-terminated, whitespace-trimmed string from `buffer` at
/// `offset`.  Returns `None` for out-of-range offsets, non-UTF-8 data, and
/// empty strings.
fn extract_string(buffer: &[u8], offset: usize) -> Option<String> {
    let slice = buffer.get(offset..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let text = std::str::from_utf8(&slice[..end]).ok()?;

    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Convert a buffer length to the `u32` expected by `DeviceIoControl`.
///
/// # Panics
///
/// Panics if `len` exceeds `u32::MAX`; all buffers used in this crate are
/// small fixed-size stack buffers, so this cannot happen in practice.
pub(crate) fn ioctl_len(len: usize) -> u32 {
    u32::try_from(len).expect("IOCTL buffer length fits in u32")
}

/// Read a little-endian `u32` from `buffer` at `offset`.
pub(crate) fn read_u32_le(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes = buffer.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Read a little-endian `i64` from `buffer` at `offset`.
pub(crate) fn read_i64_le(buffer: &[u8], offset: usize) -> Option<i64> {
    let bytes = buffer.get(offset..offset.checked_add(8)?)?;
    Some(i64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::{
        bus_type_from_raw, extract_string, physical_drive_path, read_i64_le, read_u32_le,
        string_at_offset,
    };
    use fsmnt_device::{HostDriveBusType, HostDriveError, HostDriveId};

    #[test]
    fn physical_drive_path_formats_index() {
        let path = physical_drive_path(&HostDriveId::new("0")).unwrap();
        assert_eq!(path, "\\\\.\\PhysicalDrive0");

        let path = physical_drive_path(&HostDriveId::new("12")).unwrap();
        assert_eq!(path, "\\\\.\\PhysicalDrive12");
    }

    #[test]
    fn physical_drive_path_rejects_non_numeric_ids() {
        let result = physical_drive_path(&HostDriveId::new("sda"));
        assert!(matches!(result, Err(HostDriveError::NotFound(_))));
    }

    #[test]
    fn bus_type_mapping_known_values() {
        assert_eq!(bus_type_from_raw(7), Some(HostDriveBusType::Usb));
        assert_eq!(bus_type_from_raw(11), Some(HostDriveBusType::Sata));
        assert_eq!(bus_type_from_raw(17), Some(HostDriveBusType::Nvme));
        assert_eq!(bus_type_from_raw(0), Some(HostDriveBusType::Unknown));
    }

    #[test]
    fn bus_type_mapping_unknown_value() {
        assert_eq!(bus_type_from_raw(999), None);
    }

    #[test]
    fn extract_string_stops_at_nul_and_trims() {
        let buf = b"  WDC WD10EZEX \0garbage";
        assert_eq!(extract_string(buf, 0).as_deref(), Some("WDC WD10EZEX"));
    }

    #[test]
    fn extract_string_rejects_empty_and_out_of_range() {
        assert!(extract_string(b"   \0", 0).is_none());
        assert!(extract_string(b"abc", 99).is_none());
    }

    #[test]
    fn string_at_offset_zero_means_absent() {
        assert!(string_at_offset(b"abc\0", 0).is_none());
    }

    #[test]
    fn read_le_helpers() {
        let buf = [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0x80];
        assert_eq!(read_u32_le(&buf, 0), Some(0x1234_5678));
        assert_eq!(read_i64_le(&buf, 4), Some(i64::MIN));
        assert_eq!(read_u32_le(&buf, 9), None);
        assert_eq!(read_i64_le(&buf, 5), None);
    }
}
