//! Shared assertions for driver contract tests.

use fsmnt_device::{DetectedBootSector, FilesystemDriver};

pub(crate) fn assert_supports_exactly(
    driver: &dyn FilesystemDriver,
    expected: &[DetectedBootSector],
) {
    for detected in DetectedBootSector::ALL {
        let actual = driver.supports(detected);
        let should_support = expected.contains(&detected);
        assert!(
            actual == should_support,
            "driver {} has the wrong support result for {detected:?}",
            driver.name(),
        );
    }
}
