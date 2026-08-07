//! Windows volume enumeration — maps physical-disk extents to volume GUIDs.
//!
//! Uses `FindFirstVolumeW`/`FindNextVolumeW` to discover all volumes,
//! `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` to find which physical disk and
//! byte offset each volume lives on, and
//! `GetVolumePathNamesForVolumeNameW` to resolve assigned mount points.
//!
//! This mapping lets the platform volume resolver return the operating
//! system's block view, including decrypted data from an unlocked
//! `BitLocker` volume, without assuming one volume has only one extent.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumePathNamesForVolumeNameW,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

use fsmnt_device::{HostDriveId, PhysicalExtent};

use crate::drives::{
    get_disk_sector_size, get_disk_size, ioctl_len, open_device, read_i64_le, read_u32_le,
};

/// Byte offset of `NumberOfDiskExtents` within `VOLUME_DISK_EXTENTS`.
const VDE_NUMBER_OF_EXTENTS: usize = 0;
/// Byte offset of the first `DISK_EXTENT` within `VOLUME_DISK_EXTENTS`
/// (the leading `u32` count is padded to the 8-byte alignment of
/// `DISK_EXTENT`).
const VDE_FIRST_EXTENT: usize = 8;
/// Byte offset of `DiskNumber` within a `DISK_EXTENT`.
const DE_DISK_NUMBER: usize = 0;
/// Byte offset of `StartingOffset` within a `DISK_EXTENT`.
const DE_STARTING_OFFSET: usize = 8;
/// Byte offset of `ExtentLength` within a `DISK_EXTENT`.
const DE_EXTENT_LENGTH: usize = 16;
/// Serialized size of one `DISK_EXTENT` on 64-bit Windows.
const DE_SIZE: usize = 24;
/// Buffer large enough for thousands of physical volume extents.
const VOLUME_EXTENT_BUFFER_SIZE: usize = 64 * 1024;

/// A Windows volume with every physical extent and assigned mount point.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VolumeInfo {
    /// Volume GUID path (e.g. `\\?\Volume{GUID}\`).
    pub volume_guid_path: String,
    /// Every physical disk extent contributing to the volume.
    pub extents: Vec<PhysicalExtent>,
    /// Mount points assigned to this volume (e.g. `["F:\\"]`).
    pub mount_points: Vec<String>,
    /// Readable logical length reported by the volume device.
    pub length: Option<u64>,
    /// Logical sector size reported by the volume device.
    pub sector_size: Option<u32>,
}

impl VolumeInfo {
    /// Returns the first drive letter (without trailing backslash or
    /// colon), if any.
    ///
    /// E.g. `"F:\\"` → `"F"`.
    #[must_use]
    pub fn drive_letter(&self) -> Option<&str> {
        self.mount_points.first().and_then(|mp| {
            let trimmed = mp.trim_end_matches('\\');
            let trimmed = trimmed.trim_end_matches(':');
            if trimmed.len() == 1
                && trimmed
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
            {
                Some(trimmed)
            } else {
                None
            }
        })
    }
}

/// Enumerate all volumes and their physical disk extents.
///
/// Returns volumes that have at least one disk extent (skips volumes that
/// cannot be opened or whose extents cannot be queried).
#[must_use]
pub fn enumerate_volumes() -> Vec<VolumeInfo> {
    let mut results = Vec::new();
    let mut buf = [0u16; 260];

    // SAFETY: `buf` is a live, writable UTF-16 buffer for the volume GUID
    // path; the windows crate passes its length along with the pointer.
    let Ok(handle) = (unsafe { FindFirstVolumeW(&mut buf) }) else {
        return results;
    };

    loop {
        let vol_path = wchar_to_string(&buf);
        if let Some(info) = query_volume(&vol_path) {
            results.push(info);
        }

        buf.fill(0);
        // SAFETY: `handle` is the live find-handle returned by
        // `FindFirstVolumeW` above; `buf` is a live, writable buffer.
        if unsafe { FindNextVolumeW(handle, &mut buf) }.is_err() {
            break;
        }
    }

    // SAFETY: `handle` is still open (closed exactly once, here).
    unsafe {
        let _ = FindVolumeClose(handle);
    }
    results
}

/// Find all Windows volumes backed by a physical extent.
///
/// More than one logical volume can be backed by the same partition, so this
/// lookup deliberately returns every candidate.
#[must_use]
pub fn find_volumes_for_extent(extent: &PhysicalExtent) -> Vec<VolumeInfo> {
    enumerate_volumes()
        .into_iter()
        .filter(|volume| {
            volume
                .extents
                .iter()
                .any(|candidate| candidate.has_same_start(extent))
        })
        .collect()
}

/// Query one volume's disk extent and mount points.
///
/// Returns `None` if the volume cannot be opened, its extents cannot be
/// queried, or it has no extents.
fn query_volume(vol_path: &str) -> Option<VolumeInfo> {
    // Open the volume (strip the trailing backslash for CreateFile).
    let device_path = vol_path.trim_end_matches('\\');
    let file = open_device(device_path).ok()?;

    let mut buffer = vec![0_u8; VOLUME_EXTENT_BUFFER_SIZE];
    let mut bytes_returned: u32 = 0;

    let handle = HANDLE(file.as_raw_handle());

    // SAFETY: `handle` is a valid volume handle owned by `file` for the
    // duration of the call; the output pointer/length describe `buffer`,
    // and `bytes_returned` is a valid out pointer.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            ioctl_len(buffer.len()),
            Some(&raw mut bytes_returned),
            None,
        )
    };
    result.ok()?;

    let returned = usize::try_from(bytes_returned).ok()?.min(buffer.len());
    let extents = parse_extents(&buffer[..returned])?;
    if extents.is_empty() {
        return None;
    }

    Some(VolumeInfo {
        volume_guid_path: vol_path.to_string(),
        extents,
        mount_points: get_volume_mount_points(vol_path),
        length: get_disk_size(&file),
        sector_size: get_disk_sector_size(&file),
    })
}

/// Parse every `DISK_EXTENT` from a `VOLUME_DISK_EXTENTS` buffer.
fn parse_extents(buffer: &[u8]) -> Option<Vec<PhysicalExtent>> {
    let count = usize::try_from(read_u32_le(buffer, VDE_NUMBER_OF_EXTENTS)?).ok()?;
    let extent_bytes = count.checked_mul(DE_SIZE)?;
    let required = VDE_FIRST_EXTENT.checked_add(extent_bytes)?;
    if required > buffer.len() {
        return None;
    }

    let mut extents = Vec::with_capacity(count);
    for index in 0..count {
        let base = VDE_FIRST_EXTENT.checked_add(index.checked_mul(DE_SIZE)?)?;
        let disk_number = read_u32_le(buffer, base + DE_DISK_NUMBER)?;
        let starting_offset =
            u64::try_from(read_i64_le(buffer, base + DE_STARTING_OFFSET)?).ok()?;
        let extent_length = u64::try_from(read_i64_le(buffer, base + DE_EXTENT_LENGTH)?).ok()?;
        extents.push(PhysicalExtent::new(
            HostDriveId::new(disk_number.to_string()),
            starting_offset,
            extent_length,
        ));
    }
    Some(extents)
}

/// Get all mount points (drive letters and mounted folders) for a volume
/// GUID path.
fn get_volume_mount_points(vol_path: &str) -> Vec<String> {
    let vol_wide: Vec<u16> = vol_path.encode_utf16().chain(std::iter::once(0)).collect();

    // First call with no buffer to get the required buffer size.
    let mut needed: u32 = 0;
    // SAFETY: `vol_wide` is a live NUL-terminated UTF-16 string and
    // `needed` is a valid out pointer.
    let _ = unsafe {
        GetVolumePathNamesForVolumeNameW(PCWSTR(vol_wide.as_ptr()), None, &raw mut needed)
    };

    if needed == 0 {
        return Vec::new();
    }

    let Ok(len) = usize::try_from(needed) else {
        return Vec::new();
    };
    let mut buf = vec![0u16; len];
    // SAFETY: `vol_wide` is a live NUL-terminated UTF-16 string, `buf` is
    // a live writable buffer of the size the first call requested, and
    // `needed` is a valid out pointer.
    let result = unsafe {
        GetVolumePathNamesForVolumeNameW(PCWSTR(vol_wide.as_ptr()), Some(&mut buf), &raw mut needed)
    };

    if result.is_err() {
        return Vec::new();
    }

    // The buffer is a double-NUL-terminated multi-string.
    let mut paths = Vec::new();
    let mut start = 0;
    for (i, &ch) in buf.iter().enumerate() {
        if ch == 0 {
            if i > start {
                paths.push(String::from_utf16_lossy(&buf[start..i]));
            }
            start = i + 1;
        }
    }
    paths
}

/// Convert a NUL-terminated UTF-16 buffer to a `String`.
fn wchar_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use fsmnt_device::{HostDriveId, PhysicalExtent};

    use super::{VolumeInfo, parse_extents, wchar_to_string};

    fn volume_with_mount_points(mount_points: Vec<String>) -> VolumeInfo {
        VolumeInfo {
            volume_guid_path: "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\".to_string(),
            extents: vec![PhysicalExtent::new(HostDriveId::new("0"), 0, 4096)],
            mount_points,
            length: Some(4096),
            sector_size: Some(512),
        }
    }

    #[test]
    fn drive_letter_from_letter_mount_point() {
        let vol = volume_with_mount_points(vec!["F:\\".to_string()]);
        assert_eq!(vol.drive_letter(), Some("F"));
    }

    #[test]
    fn drive_letter_none_for_folder_mount_point() {
        let vol = volume_with_mount_points(vec!["C:\\mnt\\data\\".to_string()]);
        assert_eq!(vol.drive_letter(), None);
    }

    #[test]
    fn drive_letter_none_when_unmounted() {
        let vol = volume_with_mount_points(Vec::new());
        assert_eq!(vol.drive_letter(), None);
    }

    #[test]
    fn wchar_to_string_stops_at_nul() {
        let buf: Vec<u16> = "C:\\\0junk".encode_utf16().collect();
        assert_eq!(wchar_to_string(&buf), "C:\\");
    }

    #[test]
    fn wchar_to_string_without_nul() {
        let buf: Vec<u16> = "C:".encode_utf16().collect();
        assert_eq!(wchar_to_string(&buf), "C:");
    }

    #[test]
    fn parses_every_physical_extent() {
        let mut buffer = vec![0_u8; 8 + 2 * 24];
        buffer[..4].copy_from_slice(&2_u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&0_u32.to_le_bytes());
        buffer[16..24].copy_from_slice(&4096_i64.to_le_bytes());
        buffer[24..32].copy_from_slice(&8192_i64.to_le_bytes());
        buffer[32..36].copy_from_slice(&1_u32.to_le_bytes());
        buffer[40..48].copy_from_slice(&16_384_i64.to_le_bytes());
        buffer[48..56].copy_from_slice(&32_768_i64.to_le_bytes());

        let extents = parse_extents(&buffer).expect("extents");
        assert_eq!(
            extents,
            [
                PhysicalExtent::new(HostDriveId::new("0"), 4096, 8192),
                PhysicalExtent::new(HostDriveId::new("1"), 16_384, 32_768),
            ]
        );
    }
}
