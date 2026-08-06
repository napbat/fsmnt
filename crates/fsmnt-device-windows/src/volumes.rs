//! Windows volume enumeration — maps physical-disk extents to drive letters.
//!
//! Uses `FindFirstVolumeW`/`FindNextVolumeW` to discover all volumes,
//! `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` to find which physical disk and
//! byte offset each volume lives on, and
//! `GetVolumePathNamesForVolumeNameW` to resolve drive letters.
//!
//! This mapping is what lets
//! [`open_volume_at`](fsmnt_device::HostDriveEnumerator::open_volume_at)
//! read OS-decrypted data (e.g. an unlocked `BitLocker` partition) through
//! the mounted volume (`\\.\C:`) instead of the raw physical drive.

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
    GetVolumePathNamesForVolumeNameW, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

use crate::drives::{ioctl_len, read_i64_le, read_u32_le};

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

/// A mounted Windows volume with its physical location and drive
/// letter(s).
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Volume GUID path (e.g. `\\?\Volume{GUID}\`).
    pub volume_guid_path: String,
    /// Physical disk number (e.g. `1` for `\\.\PhysicalDrive1`).
    pub disk_number: u32,
    /// Byte offset on the physical disk where this volume starts.
    pub starting_offset: u64,
    /// Length of the volume extent in bytes.
    pub extent_length: u64,
    /// Mount points assigned to this volume (e.g. `["F:\\"]`).
    pub mount_points: Vec<String>,
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

/// Enumerate all mounted volumes and their physical disk extents.
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

/// Find the mounted volume for a specific physical disk + byte offset.
///
/// This is the primary lookup used when opening partitions: given that a
/// partition lives on `PhysicalDrive{disk_number}` at `offset`, find the
/// Windows volume (if any) that corresponds to it.
#[must_use]
pub fn find_volume_for_extent(disk_number: u32, offset: u64) -> Option<VolumeInfo> {
    enumerate_volumes()
        .into_iter()
        .find(|v| v.disk_number == disk_number && v.starting_offset == offset)
}

/// Query one volume's disk extent and mount points.
///
/// Returns `None` if the volume cannot be opened, its extents cannot be
/// queried, or it has no extents.
fn query_volume(vol_path: &str) -> Option<VolumeInfo> {
    // Open the volume (strip the trailing backslash for CreateFile).
    let device_path = vol_path.trim_end_matches('\\');
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .open(device_path)
        .ok()?;

    let mut buffer = [0u8; 256];
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

    // Parse `VOLUME_DISK_EXTENTS` straight from the byte buffer: the
    // structure is variable-length and the buffer is only byte-aligned, so
    // reading through a `#[repr(C)]` struct pointer would be an unaligned
    // (undefined-behavior) read.
    if read_u32_le(&buffer, VDE_NUMBER_OF_EXTENTS)? == 0 {
        return None;
    }

    // Use the first extent (multi-extent/spanned volumes are rare).
    let disk_number = read_u32_le(&buffer, VDE_FIRST_EXTENT + DE_DISK_NUMBER)?;
    let starting_offset =
        u64::try_from(read_i64_le(&buffer, VDE_FIRST_EXTENT + DE_STARTING_OFFSET)?).ok()?;
    let extent_length =
        u64::try_from(read_i64_le(&buffer, VDE_FIRST_EXTENT + DE_EXTENT_LENGTH)?).ok()?;

    Some(VolumeInfo {
        volume_guid_path: vol_path.to_string(),
        disk_number,
        starting_offset,
        extent_length,
        mount_points: get_volume_mount_points(vol_path),
    })
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
    use super::{VolumeInfo, wchar_to_string};

    fn volume_with_mount_points(mount_points: Vec<String>) -> VolumeInfo {
        VolumeInfo {
            volume_guid_path: "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\".to_string(),
            disk_number: 0,
            starting_offset: 0,
            extent_length: 0,
            mount_points,
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
}
