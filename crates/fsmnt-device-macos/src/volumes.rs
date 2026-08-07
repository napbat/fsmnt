//! macOS logical-volume discovery through the `IOKit` media graph.

use std::ffi::CStr;
use std::path::PathBuf;

use fsmnt_device::{
    HostDriveResult, HostVolumeResolver, LogicalVolume, LogicalVolumeId, PhysicalExtent,
};

use crate::drives::{MacOsHostDrives, open_device};
use crate::iokit;

impl HostVolumeResolver for MacOsHostDrives {
    type VolumeReader = std::fs::File;

    fn logical_volumes(extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        Ok(iokit::logical_media_for_extent(extent)
            .into_iter()
            .map(|media| {
                let device_path = preferred_device_path(&media.bsd_name);
                let mut volume = LogicalVolume::new(
                    LogicalVolumeId::new(media.id),
                    device_path,
                    vec![extent.clone()],
                )
                .with_mount_points(mount_points_for(&media.bsd_name))
                .with_length(media.length);
                if let Some(sector_size) = media.sector_size {
                    volume = volume.with_sector_size(sector_size);
                }
                volume
            })
            .collect())
    }

    fn open_logical_volume(volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        open_device(&volume.device_path().to_string_lossy())
    }
}

fn preferred_device_path(bsd_name: &str) -> PathBuf {
    let raw = PathBuf::from(format!("/dev/r{bsd_name}"));
    if raw.exists() {
        raw
    } else {
        PathBuf::from("/dev").join(bsd_name)
    }
}

fn mount_points_for(bsd_name: &str) -> Vec<PathBuf> {
    let expected_source = format!("/dev/{bsd_name}");
    mounted_filesystems()
        .into_iter()
        .filter_map(|mount| (mount.source == expected_source).then(|| PathBuf::from(mount.target)))
        .collect()
}

struct MountedFilesystem {
    source: String,
    target: String,
}

fn mounted_filesystems() -> Vec<MountedFilesystem> {
    let mut entries = std::ptr::null_mut();
    // SAFETY: `entries` is a valid out-pointer. `getmntinfo` returns a
    // process-owned array that remains valid until the next call.
    let count = unsafe { libc::getmntinfo(&raw mut entries, libc::MNT_NOWAIT) };
    let Ok(count) = usize::try_from(count) else {
        return Vec::new();
    };
    if entries.is_null() || count == 0 {
        return Vec::new();
    }

    // SAFETY: a positive `getmntinfo` result is the number of initialized
    // `statfs` records beginning at `entries`.
    let entries = unsafe { std::slice::from_raw_parts(entries, count) };
    entries
        .iter()
        .filter_map(|entry| {
            let source = c_char_array_to_string(&entry.f_mntfromname)?;
            let target = c_char_array_to_string(&entry.f_mntonname)?;
            Some(MountedFilesystem { source, target })
        })
        .collect()
}

fn c_char_array_to_string<const N: usize>(characters: &[libc::c_char; N]) -> Option<String> {
    // SAFETY: macOS initializes both `statfs` path arrays as NUL-terminated
    // C strings within their fixed-size storage.
    let value = unsafe { CStr::from_ptr(characters.as_ptr()) };
    value.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::preferred_device_path;

    #[test]
    fn unavailable_raw_node_falls_back_to_block_path() {
        assert_eq!(
            preferred_device_path("definitely-not-a-real-fsmnt-device"),
            Path::new("/dev/definitely-not-a-real-fsmnt-device")
        );
    }
}
