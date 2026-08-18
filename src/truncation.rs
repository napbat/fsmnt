//! Comparing what a filesystem claims to be against what the media carries.
//!
//! A partial acquisition — an aborted `dd`, a dump cut at a device's
//! reported size, a partition table describing media that was never
//! captured — still opens: the superblock is at the front, so the driver
//! mounts a filesystem whose tail simply is not there. Reads fail later, one
//! file at a time, which is easy to misread as filesystem corruption.
//!
//! [`missing_filesystem_bytes`] turns that into a number that can be
//! reported at mount time.

/// Bytes a filesystem claims for itself that its opened window does not
/// carry.
///
/// `claimed` is what the filesystem's own superblock or boot sector reports
/// (see [`TargetFilesystem::total_size`](fsmnt_core::TargetFilesystem::total_size));
/// `available` is the length of the byte window it was opened in. Returns
/// `None` when the filesystem fits, and when it does not say how big it is.
#[must_use]
pub fn missing_filesystem_bytes(claimed: Option<u64>, available: u64) -> Option<u64> {
    let missing = claimed?.checked_sub(available)?;
    (missing > 0).then_some(missing)
}

#[cfg(test)]
mod tests {
    use super::missing_filesystem_bytes;

    #[test]
    fn a_filesystem_that_fits_is_not_truncated() {
        assert_eq!(missing_filesystem_bytes(Some(4096), 4096), None);
        assert_eq!(missing_filesystem_bytes(Some(4096), 8192), None);
    }

    #[test]
    fn a_filesystem_larger_than_its_window_reports_the_difference() {
        assert_eq!(
            missing_filesystem_bytes(Some(1_560_440_832), 1_438_777_344),
            Some(121_663_488)
        );
    }

    #[test]
    fn a_filesystem_that_does_not_state_its_size_is_never_truncated() {
        assert_eq!(missing_filesystem_bytes(None, 0), None);
    }

    #[test]
    fn an_empty_window_is_missing_the_whole_filesystem() {
        assert_eq!(missing_filesystem_bytes(Some(4096), 0), Some(4096));
    }
}
