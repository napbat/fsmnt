//! Recovery of deleted index entries from slack space.
//!
//! When files are deleted from an NTFS directory, their index entries are removed from
//! the B-tree but the underlying bytes are **not zeroed**. The gap between `index_data_size`
//! (active entries) and `index_allocated_size` (allocated space) is slack space that may
//! contain recoverable file names, timestamps, and MFT references.
//!
//! # Example
//!
//! ```no_run
//! # use fs_ntfs::{Ntfs, NtfsAttribute, NtfsSlackEntryScanner, SlackRecoveryConfig};
//! # use fs_ntfs::structured_values::NtfsIndexRoot;
//! # let mut fs = std::io::Cursor::new(vec![]);
//! # let mut ntfs = Ntfs::new(&mut fs).unwrap();
//! # let root_dir = ntfs.root_directory(&mut fs).unwrap();
//! // Get INDEX_ROOT from the directory's attributes
//! # let mut attrs = root_dir.attributes_raw();
//! # let attr = attrs.next().unwrap().unwrap();
//! # let index_root = attr.resident_structured_value::<NtfsIndexRoot>().unwrap();
//! let config = SlackRecoveryConfig::default();
//! let parent_record = 5; // root directory
//! let scanner = NtfsSlackEntryScanner::new(
//!     index_root.slack_data(),
//!     index_root.slack_position(),
//!     config,
//!     parent_record,
//! );
//! for entry in scanner {
//!     println!("Recovered: {} (score {})", entry.file_name().name(), entry.validation().score());
//! }
//! ```

use alloc::boxed::Box;

use crate::error::Result;
use crate::file_reference::NtfsFileReference;
use crate::index_entry::NtfsIndexEntry;
use crate::indexes::{NtfsIndexEntryHasFileReference, NtfsIndexEntryKey, NtfsIndexEntryType};
use crate::structured_values::NtfsFileName;
use crate::time::{NtfsTime, TimestampBounds};
use crate::types::NtfsPosition;

/// Minimum size of an index entry that can contain a `FILE_NAME` key.
///
/// 16 bytes index entry header + 66 bytes `FILE_NAME` header + 2 bytes minimum name (1 UTF-16 char).
const MIN_ENTRY_SIZE: usize = 84;

/// Size of a `FILE_NAME` header (without the variable-length name).
const FILE_NAME_HEADER_SIZE: usize = 66;

/// Size of the index entry header before the key region.
const INDEX_ENTRY_HEADER_SIZE: usize = 16;

/// Tuneable heuristic thresholds for slack entry recovery.
#[derive(Clone, Copy, Debug)]
pub struct SlackRecoveryConfig {
    /// Plausible NTFS timestamp range for recovered entries.
    pub timestamp_bounds: TimestampBounds,
    /// If true, require that the parent directory reference in the `FILE_NAME`
    /// matches the expected directory. Default: true
    pub require_parent_match: bool,
    /// Upper bound for MFT record numbers. Default: `1_000_000`
    pub max_mft_record: u64,
}

impl Default for SlackRecoveryConfig {
    fn default() -> Self {
        Self {
            timestamp_bounds: TimestampBounds::default(),
            require_parent_match: true,
            max_mft_record: 1_000_000,
        }
    }
}

/// Per-entry heuristic validation results.
///
/// Each field records whether one aspect of the recovered entry looks plausible.
#[derive(Clone, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean reports an independent slack-entry validation result"
)]
pub struct EntryValidation {
    /// Namespace byte is 0–3 (always true if parsing succeeded).
    pub namespace_valid: bool,
    /// `name_length` > 0 and first UTF-16 character is nonzero.
    pub name_valid: bool,
    /// `allocated_size` >= `data_size`.
    pub sizes_consistent: bool,
    /// All 4 timestamps fall within the configured plausible range.
    pub timestamps_plausible: bool,
    /// Parent directory reference matches the expected directory.
    pub parent_matches: bool,
    /// File record number is within the configured maximum.
    pub mft_ref_in_range: bool,
}

impl EntryValidation {
    /// Returns `true` if all heuristic checks pass.
    #[must_use]
    pub fn all_valid(&self) -> bool {
        self.namespace_valid
            && self.name_valid
            && self.sizes_consistent
            && self.timestamps_plausible
            && self.parent_matches
            && self.mft_ref_in_range
    }

    /// Returns the number of passing heuristic checks (0–6).
    #[must_use]
    pub fn score(&self) -> u8 {
        u8::from(self.namespace_valid)
            + u8::from(self.name_valid)
            + u8::from(self.sizes_consistent)
            + u8::from(self.timestamps_plausible)
            + u8::from(self.parent_matches)
            + u8::from(self.mft_ref_in_range)
    }
}

/// A single recovered entry from index slack space.
#[derive(Clone, Debug)]
pub struct NtfsRecoveredEntry {
    file_reference: NtfsFileReference,
    file_name: NtfsFileName,
    validation: EntryValidation,
    position: NtfsPosition,
}

impl NtfsRecoveredEntry {
    /// The MFT file reference of the recovered entry.
    #[must_use]
    pub fn file_reference(&self) -> &NtfsFileReference {
        &self.file_reference
    }

    /// The parsed `FILE_NAME` attribute from the recovered entry.
    #[must_use]
    pub fn file_name(&self) -> &NtfsFileName {
        &self.file_name
    }

    /// Heuristic validation results for this entry.
    #[must_use]
    pub fn validation(&self) -> &EntryValidation {
        &self.validation
    }

    /// Disk position where this entry was found.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }
}

/// A directory entry that is either active (from the B-tree index) or recovered from slack space.
///
/// This enum allows callers to process both live and recovered entries through a uniform
/// interface when combining results from [`NtfsIndex::entries`] and
/// [`NtfsFile::recover_directory_slack`].
///
/// [`NtfsIndex::entries`]: crate::NtfsIndex::entries
/// [`NtfsFile::recover_directory_slack`]: crate::NtfsFile::recover_directory_slack
#[derive(Clone, Debug)]
pub enum NtfsDirectoryEntry<'a, E: NtfsIndexEntryType> {
    /// Entry from the active B-tree index.
    Active(NtfsIndexEntry<'a, E>),
    /// Entry recovered from index slack space.
    Recovered(Box<NtfsRecoveredEntry>),
}

impl<E> NtfsDirectoryEntry<'_, E>
where
    E: NtfsIndexEntryType<KeyType = NtfsFileName> + NtfsIndexEntryHasFileReference,
{
    /// Returns `true` if this is an active entry from the B-tree index.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    /// Returns `true` if this is an entry recovered from slack space.
    #[must_use]
    pub fn is_recovered(&self) -> bool {
        matches!(self, Self::Recovered(_))
    }

    /// Returns the file name from either variant.
    ///
    /// For active entries, this reads the key from the index entry.
    /// For recovered entries, this returns the parsed file name directly.
    #[must_use]
    pub fn file_name(&self) -> Option<Result<NtfsFileName>> {
        match self {
            Self::Active(entry) => entry.key(),
            Self::Recovered(entry) => Some(Ok(entry.file_name().clone())),
        }
    }
}

/// Scans index slack space for recoverable deleted entries.
///
/// Iterates over a byte slice of slack space, attempting to parse index entries
/// containing `FILE_NAME` keys. Uses heuristic validation to assess confidence in
/// each recovered entry.
pub struct NtfsSlackEntryScanner<'s> {
    data: &'s [u8],
    position: NtfsPosition,
    offset: usize,
    config: SlackRecoveryConfig,
    parent_record_number: u64,
}

impl<'s> NtfsSlackEntryScanner<'s> {
    /// Creates a new scanner over the given slack space data.
    ///
    /// - `data`: Slack byte slice (from `slack_data()`)
    /// - `position`: Disk position where the slack space starts (from `slack_position()`)
    /// - `config`: Heuristic thresholds
    /// - `parent_record_number`: Expected parent directory MFT record number
    #[must_use]
    pub fn new(
        data: &'s [u8],
        position: NtfsPosition,
        config: SlackRecoveryConfig,
        parent_record_number: u64,
    ) -> Self {
        Self {
            data,
            position,
            offset: 0,
            config,
            parent_record_number,
        }
    }

    /// Try to parse an entry at the current offset. Returns `Some(entry)` on success
    /// and the number of bytes to advance, or `None` with advance-by-4.
    fn try_parse_at(&self, offset: usize) -> Option<(NtfsRecoveredEntry, usize)> {
        let remaining = self.data.len() - offset;
        if remaining < MIN_ENTRY_SIZE {
            return None;
        }

        let entry_data = &self.data[offset..];

        // Read index entry header fields
        let index_entry_length = usize::from(u16::from_le_bytes([entry_data[8], entry_data[9]]));
        let key_length = usize::from(u16::from_le_bytes([entry_data[10], entry_data[11]]));

        if key_length > 0 {
            // Normal path: key_length is present
            self.try_parse_normal(entry_data, offset, index_entry_length, key_length)
        } else {
            // Zeroed key_length path: try to reconstruct from name_length
            self.try_parse_zeroed_key(entry_data, offset)
        }
    }

    fn try_parse_normal(
        &self,
        entry_data: &[u8],
        offset: usize,
        index_entry_length: usize,
        key_length: usize,
    ) -> Option<(NtfsRecoveredEntry, usize)> {
        let remaining = entry_data.len();

        // Validate index_entry_length
        if index_entry_length < MIN_ENTRY_SIZE || index_entry_length > remaining {
            return None;
        }
        if !index_entry_length.is_multiple_of(4) {
            return None;
        }

        // Validate key_length (FILE_NAME minimum is 68 = header 66 + 1 char * 2 bytes)
        if key_length < 68 || key_length > index_entry_length - INDEX_ENTRY_HEADER_SIZE {
            return None;
        }

        let key_start = INDEX_ENTRY_HEADER_SIZE;
        let key_end = key_start + key_length;
        if key_end > remaining {
            return None;
        }

        let key_slice = &entry_data[key_start..key_end];
        let entry_position = self.position + offset;
        let key_position = entry_position + key_start;

        let file_name = NtfsFileName::key_from_slice(key_slice, key_position).ok()?;
        let file_ref_bytes: [u8; 8] = entry_data[..8].try_into().ok()?;
        let file_reference = NtfsFileReference::new(file_ref_bytes);

        let validation = self.validate(&file_name, file_reference);
        let entry = NtfsRecoveredEntry {
            file_reference,
            file_name,
            validation,
            position: entry_position,
        };

        Some((entry, index_entry_length))
    }

    fn try_parse_zeroed_key(
        &self,
        entry_data: &[u8],
        offset: usize,
    ) -> Option<(NtfsRecoveredEntry, usize)> {
        let remaining = entry_data.len();

        // Offset 80 = INDEX_ENTRY_HEADER_SIZE(16) + FILE_NAME name_length offset(64)
        if remaining < 81 {
            return None;
        }

        let name_length = usize::from(entry_data[80]);
        if name_length == 0 {
            return None;
        }

        let estimated_key_length = FILE_NAME_HEADER_SIZE + name_length * 2;
        let estimated_entry_length = round_up_4(INDEX_ENTRY_HEADER_SIZE + estimated_key_length);

        if estimated_entry_length > remaining || estimated_entry_length < MIN_ENTRY_SIZE {
            return None;
        }

        let key_start = INDEX_ENTRY_HEADER_SIZE;
        let key_end = key_start + estimated_key_length;
        if key_end > remaining {
            return None;
        }

        let key_slice = &entry_data[key_start..key_end];
        let entry_position = self.position + offset;
        let key_position = entry_position + key_start;

        let file_name = NtfsFileName::key_from_slice(key_slice, key_position).ok()?;
        let file_ref_bytes: [u8; 8] = entry_data[..8].try_into().ok()?;
        let file_reference = NtfsFileReference::new(file_ref_bytes);

        let validation = self.validate(&file_name, file_reference);
        let entry = NtfsRecoveredEntry {
            file_reference,
            file_name,
            validation,
            position: entry_position,
        };

        Some((entry, estimated_entry_length))
    }

    fn validate(
        &self,
        file_name: &NtfsFileName,
        file_reference: NtfsFileReference,
    ) -> EntryValidation {
        // namespace_valid: if key_from_slice succeeded, the namespace was validated
        let namespace_valid = true;

        // name_valid: name_length > 0 and first UTF-16 char is nonzero
        let name_valid = file_name.name_length() > 0 && {
            let name = file_name.name();
            let name_str = name.to_string_lossy();
            !name_str.is_empty() && !name_str.starts_with('\0')
        };

        // sizes_consistent: allocated_size >= data_size
        let sizes_consistent = file_name.allocated_size() >= file_name.data_size();

        // timestamps_plausible: all 4 timestamps within range
        let timestamps_plausible = self.timestamp_in_range(file_name.creation_time())
            && self.timestamp_in_range(file_name.modification_time())
            && self.timestamp_in_range(file_name.mft_record_modification_time())
            && self.timestamp_in_range(file_name.access_time());

        // parent_matches
        let parent_matches = if self.config.require_parent_match {
            file_name.parent_directory_reference().file_record_number() == self.parent_record_number
        } else {
            true
        };

        // mft_ref_in_range
        let mft_ref_in_range = file_reference.file_record_number() <= self.config.max_mft_record;

        EntryValidation {
            namespace_valid,
            name_valid,
            sizes_consistent,
            timestamps_plausible,
            parent_matches,
            mft_ref_in_range,
        }
    }

    fn timestamp_in_range(&self, time: NtfsTime) -> bool {
        self.config.timestamp_bounds.contains(time.nt_timestamp())
    }
}

impl Iterator for NtfsSlackEntryScanner<'_> {
    type Item = NtfsRecoveredEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.data.len() - self.offset < MIN_ENTRY_SIZE {
                return None;
            }

            if let Some((entry, advance)) = self.try_parse_at(self.offset) {
                self.offset += advance;
                return Some(entry);
            }

            // Advance by 4 (NTFS alignment) and try again
            self.offset += 4;
        }
    }
}

/// Round up to the next multiple of 4.
fn round_up_4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
#[path = "slack_recovery_tests/mod.rs"]
mod tests;
