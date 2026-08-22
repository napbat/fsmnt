//! Directory-listing filtering shared by the mount backends.

use std::collections::HashSet;

use crate::filesystem::{FsEntry, FsEntryFlags};

/// Collects [`FsEntry::file_id`] values for entries that have a long
/// (non-8.3) name.  Used to suppress duplicate short-name entries in
/// directory listings.
fn long_name_ids(entries: &[FsEntry]) -> HashSet<u64> {
    if !entries
        .iter()
        .any(|entry| entry.flags.contains(FsEntryFlags::SHORT_NAME) && entry.file_id.is_some())
    {
        return HashSet::new();
    }

    entries
        .iter()
        .filter(|e| !e.flags.contains(FsEntryFlags::SHORT_NAME))
        .filter_map(|e| e.file_id)
        .collect()
}

/// Returns `true` if the entry should be hidden from mount directory
/// listings.
///
/// Filters out:
/// - DOS 8.3 short-name duplicates (when a long name exists for the
///   same file)
/// - Filesystem system/metadata files (e.g. NTFS `$MFT`, `$Bitmap`)
fn should_hide(entry: &FsEntry, long_ids: &HashSet<u64>) -> bool {
    // Suppress short-name duplicates.
    if entry.flags.contains(FsEntryFlags::SHORT_NAME)
        && entry.file_id.is_some_and(|id| long_ids.contains(&id))
    {
        return true;
    }

    // Hide filesystem metadata files (set by the parser).
    if entry.flags.contains(FsEntryFlags::SYSTEM_FILE) {
        return true;
    }

    false
}

/// Iterates over the entries that should be displayed in a mounted volume.
///
/// Hides DOS 8.3 short-name duplicates (when a long name exists for the
/// same file) and filesystem system/metadata files (e.g. NTFS `$MFT`).
/// This is the single source of truth for which entries are visible; both
/// the Dokan and FUSE mount backends call this.
///
/// The returned iterator borrows the source listing and does not allocate a
/// second vector. A lookup set is allocated only when the listing contains a
/// DOS short name whose file identifier could match a long name.
pub fn filter_entries(entries: &[FsEntry]) -> impl Iterator<Item = &FsEntry> {
    let long_ids = long_name_ids(entries);
    entries
        .iter()
        .filter(move |entry| !should_hide(entry, &long_ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::FsMetadata;

    fn entry(name: &str, flags: FsEntryFlags, file_id: Option<u64>) -> FsEntry {
        FsEntry {
            name: name.to_string(),
            path: name.into(),
            flags,
            file_id,
            metadata: FsMetadata::default(),
        }
    }

    #[test]
    fn keeps_normal_entries() {
        let entries = vec![
            entry("a.txt", FsEntryFlags::empty(), Some(1)),
            entry("b.txt", FsEntryFlags::empty(), Some(2)),
        ];
        assert_eq!(filter_entries(&entries).count(), 2);
    }

    #[test]
    fn hides_short_name_duplicate_of_long_name() {
        let entries = vec![
            entry("LongFileName.txt", FsEntryFlags::empty(), Some(7)),
            entry("LONGFI~1.TXT", FsEntryFlags::SHORT_NAME, Some(7)),
        ];
        let visible: Vec<_> = filter_entries(&entries).collect();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "LongFileName.txt");
    }

    #[test]
    fn keeps_short_name_without_long_counterpart() {
        let entries = vec![entry("LONELY~1.TXT", FsEntryFlags::SHORT_NAME, Some(9))];
        assert_eq!(filter_entries(&entries).count(), 1);
    }

    #[test]
    fn hides_system_files() {
        let entries = vec![
            entry("$MFT", FsEntryFlags::SYSTEM_FILE, Some(0)),
            entry("normal.txt", FsEntryFlags::empty(), Some(1)),
        ];
        let visible: Vec<_> = filter_entries(&entries).collect();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "normal.txt");
    }

    #[test]
    fn short_name_without_file_id_is_kept() {
        let entries = vec![
            entry("LongFileName.txt", FsEntryFlags::empty(), None),
            entry("LONGFI~1.TXT", FsEntryFlags::SHORT_NAME, None),
        ];
        assert_eq!(filter_entries(&entries).count(), 2);
    }
}
