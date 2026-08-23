//! Bounded metadata caching for the read-only Dokan namespace.

use std::collections::{HashMap, VecDeque};

use fsmnt_core::FsMetadata;

/// Number of recently observed paths retained across Dokan handles.
const PATH_CACHE_CAPACITY: usize = 16 * 1024;

/// Result of resolving a path in the immutable mounted namespace.
#[derive(Clone)]
pub(super) enum CachedMetadata {
    /// The path exists with this directory-entry metadata.
    Found(FsMetadata),
    /// The path did not exist when the backend resolved it.
    Missing,
}

/// FIFO-bounded cache shared by the short-lived handles Windows opens while
/// browsing a directory.
pub(super) struct MetadataCache {
    entries: HashMap<Box<str>, CachedMetadata>,
    insertion_order: VecDeque<Box<str>>,
    capacity: usize,
}

impl MetadataCache {
    /// Creates a cache with the production capacity.
    pub(super) fn new() -> Self {
        Self::with_capacity(PATH_CACHE_CAPACITY)
    }

    /// Returns a detached copy so callers do not retain the cache lock.
    pub(super) fn get(&self, path: &str) -> Option<CachedMetadata> {
        self.entries.get(path).cloned()
    }

    /// Remembers metadata obtained from an open or parent-directory listing.
    pub(super) fn insert_found(&mut self, path: &str, metadata: FsMetadata) {
        self.insert(path, CachedMetadata::Found(metadata));
    }

    /// Remembers a normal namespace miss, including Windows shell probes.
    pub(super) fn insert_missing(&mut self, path: &str) {
        self.insert(path, CachedMetadata::Missing);
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, path: &str, value: CachedMetadata) {
        if let Some(cached) = self.entries.get_mut(path) {
            *cached = value;
            return;
        }

        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(oldest.as_ref());
        }

        let path: Box<str> = path.into();
        self.insertion_order.push_back(path.clone());
        self.entries.insert(path, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedMetadata, MetadataCache};
    use fsmnt_core::FsMetadata;

    #[test]
    fn evicts_the_oldest_path_at_capacity() {
        let mut cache = MetadataCache::with_capacity(2);
        cache.insert_found("one", FsMetadata::default());
        cache.insert_missing("two");
        cache.insert_found("three", FsMetadata::default());

        assert!(cache.get("one").is_none());
        assert!(matches!(cache.get("two"), Some(CachedMetadata::Missing)));
        assert!(matches!(cache.get("three"), Some(CachedMetadata::Found(_))));
    }

    #[test]
    fn replaces_an_existing_path_without_evicting_another() {
        let mut cache = MetadataCache::with_capacity(2);
        cache.insert_missing("one");
        cache.insert_missing("two");
        cache.insert_found("one", FsMetadata::default());

        assert!(matches!(cache.get("one"), Some(CachedMetadata::Found(_))));
        assert!(matches!(cache.get("two"), Some(CachedMetadata::Missing)));
    }
}
