//! Errors produced while selecting and opening image containers.

use std::error::Error;
use std::path::{Path, PathBuf};

/// Failure to open a supported disk-image container.
#[derive(Debug, thiserror::Error)]
#[error("failed to open image {path:?}: {source}")]
pub struct ImageOpenError {
    path: PathBuf,
    #[source]
    source: Box<dyn Error + Send + Sync>,
}

impl ImageOpenError {
    pub(super) fn new(path: &Path, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            path: path.to_path_buf(),
            source: Box::new(source),
        }
    }

    /// Path whose image container could not be opened.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}
