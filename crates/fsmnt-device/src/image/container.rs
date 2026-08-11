//! Shared decoded-media contract for disk-image containers.

use crate::DeviceReader;

use super::format::ImageFormat;

/// Decoded logical-media interface implemented by every image container.
///
/// Implementations expose the virtual disk's byte stream, not container
/// headers, compression chunks, allocation tables, or sparse-block storage.
/// The trait is object-safe so callers can pass a detected image through the
/// same device and filesystem layers as a raw block reader.
pub trait ImageContainer: DeviceReader {
    /// Container format used by this image.
    #[must_use]
    fn format(&self) -> ImageFormat;

    /// Length of the decoded logical media in bytes.
    #[must_use]
    fn len(&self) -> u64;

    /// Whether the decoded logical media is empty.
    #[must_use]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
