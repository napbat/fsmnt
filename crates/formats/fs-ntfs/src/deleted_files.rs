//! Deleted file recovery from MFT records.
//!
//! Scans the Master File Table for records that are no longer in use
//! (deleted files) and extracts their metadata, data run locations,
//! and cluster allocation status.
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::fs::File;
//! use fs_ntfs::Ntfs;
//!
//! let mut fs = File::open("ntfs.img")?;
//! let ntfs = Ntfs::new(&mut fs)?;
//! let mut scanner = ntfs.deleted_files(&mut fs)?;
//! while let Some(result) = scanner.next(&ntfs, &mut fs) {
//!     let deleted = result?;
//!     println!(
//!         "Record {}: {:?} (score: {})",
//!         deleted.record_number,
//!         deleted.name,
//!         deleted.assessment.score()
//!     );
//! }
//! # Ok(())
//! # }
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use bitflags::bitflags;

use crate::Ntfs;
use crate::cluster_bitmap::NtfsClusterBitmap;
use crate::error::Result;
use crate::file::NtfsFileFlags;
use crate::mft::NtfsMftEntries;
use crate::time::{NtfsTime, TimestampBounds};

/// Number of NTFS system metafile records (0 through 23).
const SYSTEM_RECORD_COUNT: u64 = 24;

/// Allocation status of clusters in a deleted file's data run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterStatus {
    /// All clusters are unallocated; data is likely intact.
    AllFree,
    /// All clusters have been reallocated; data is likely overwritten.
    AllAllocated,
    /// Some clusters are free, some are allocated.
    Mixed,
    /// Status could not be determined (sparse run or bitmap read error).
    Unknown,
}

/// A single contiguous run of clusters from a deleted file's `$DATA`
/// attribute.
#[derive(Clone, Debug)]
pub struct DeletedDataRun {
    /// Starting cluster number (LCN).
    pub cluster_offset: u64,
    /// Number of clusters in this run.
    pub cluster_count: u64,
    /// Allocation status from the cluster bitmap.
    pub status: ClusterStatus,
}

bitflags! {
    /// Individual checks and parse outcomes recorded during deleted-file recovery.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct RecoveryChecks: u16 {
        /// The MFT record had a valid `FILE` signature after USA fixup.
        const VALID_SIGNATURE = 1 << 0;
        /// At least one attribute was parsed without error.
        const ATTRIBUTES_PARSEABLE = 1 << 1;
        /// A `$FILE_NAME` attribute was found with a non-empty name.
        const NAME_RECOVERED = 1 << 2;
        /// All recovered timestamps fall within the configured plausible range.
        const TIMESTAMPS_PLAUSIBLE = 1 << 3;
        /// The `$DATA` attribute contains non-resident data runs.
        const DATA_RUNS_PRESENT = 1 << 4;
        /// All data-run clusters are still unallocated.
        const CLUSTERS_FREE = 1 << 5;
        /// The `$FILE_NAME` and `$DATA` logical sizes agree.
        const SIZES_CONSISTENT = 1 << 6;
        /// The `$FILE_NAME` attribute existed but could not be parsed.
        const NAME_PARSE_FAILED = 1 << 7;
        /// The `$STANDARD_INFORMATION` attribute existed but could not be parsed.
        const INFO_PARSE_FAILED = 1 << 8;
    }
}

/// Heuristic assessment of how recoverable a deleted file is.
///
/// Each status accessor reports one validation check. Use [`Self::score`] for
/// a combined 0-7 numeric score or [`Self::fully_recoverable`] to require every
/// recoverability check to pass.
#[derive(Clone, Debug)]
pub struct RecoveryAssessment {
    checks: RecoveryChecks,
}

impl RecoveryAssessment {
    /// Returns whether the record retained a valid `FILE` signature.
    #[must_use]
    pub fn valid_signature(&self) -> bool {
        self.checks.contains(RecoveryChecks::VALID_SIGNATURE)
    }

    /// Returns whether at least one attribute could be parsed.
    #[must_use]
    pub fn attributes_parseable(&self) -> bool {
        self.checks.contains(RecoveryChecks::ATTRIBUTES_PARSEABLE)
    }

    /// Returns whether a usable `$FILE_NAME` value was recovered.
    #[must_use]
    pub fn name_recovered(&self) -> bool {
        self.checks.contains(RecoveryChecks::NAME_RECOVERED)
    }

    /// Returns whether every recovered timestamp is plausible.
    #[must_use]
    pub fn timestamps_plausible(&self) -> bool {
        self.checks.contains(RecoveryChecks::TIMESTAMPS_PLAUSIBLE)
    }

    /// Returns whether the record contains non-resident data runs.
    #[must_use]
    pub fn data_runs_present(&self) -> bool {
        self.checks.contains(RecoveryChecks::DATA_RUNS_PRESENT)
    }

    /// Returns whether every recovered data-run cluster is still free.
    #[must_use]
    pub fn clusters_free(&self) -> bool {
        self.checks.contains(RecoveryChecks::CLUSTERS_FREE)
    }

    /// Returns whether the `$FILE_NAME` and `$DATA` sizes are consistent.
    #[must_use]
    pub fn sizes_consistent(&self) -> bool {
        self.checks.contains(RecoveryChecks::SIZES_CONSISTENT)
    }

    /// Returns whether a present `$FILE_NAME` attribute failed to parse.
    #[must_use]
    pub fn name_parse_failed(&self) -> bool {
        self.checks.contains(RecoveryChecks::NAME_PARSE_FAILED)
    }

    /// Returns whether a present `$STANDARD_INFORMATION` attribute failed to parse.
    #[must_use]
    pub fn info_parse_failed(&self) -> bool {
        self.checks.contains(RecoveryChecks::INFO_PARSE_FAILED)
    }

    /// Combined score from 0 (no checks pass) to 7 (all checks pass).
    #[must_use]
    pub fn score(&self) -> u8 {
        u8::from(self.valid_signature())
            + u8::from(self.attributes_parseable())
            + u8::from(self.name_recovered())
            + u8::from(self.timestamps_plausible())
            + u8::from(self.data_runs_present())
            + u8::from(self.clusters_free())
            + u8::from(self.sizes_consistent())
    }

    /// Returns `true` if every check passes.
    #[must_use]
    pub fn fully_recoverable(&self) -> bool {
        self.score() == 7
    }
}

/// Metadata recovered from a deleted MFT record.
#[derive(Clone, Debug)]
pub struct NtfsDeletedFile {
    /// MFT record number.
    pub record_number: u64,
    /// Sequence number (incremented on each delete/reuse cycle).
    pub sequence_number: u16,
    /// Whether this record was a directory.
    pub is_directory: bool,
    /// Win32 file name, if the `$FILE_NAME` attribute was parseable.
    pub name: Option<String>,
    /// Parent directory MFT record number, from `$FILE_NAME`.
    pub parent_record_number: Option<u64>,
    /// File creation time from `$STANDARD_INFORMATION`.
    pub created: Option<NtfsTime>,
    /// File modification time from `$STANDARD_INFORMATION`.
    pub modified: Option<NtfsTime>,
    /// Last access time from `$STANDARD_INFORMATION`.
    pub accessed: Option<NtfsTime>,
    /// MFT record modification time from `$STANDARD_INFORMATION`.
    pub mft_modified: Option<NtfsTime>,
    /// Logical file size in bytes.
    pub logical_size: u64,
    /// Cluster run locations from the `$DATA` attribute.
    pub data_runs: Vec<DeletedDataRun>,
    /// Heuristic recoverability assessment.
    pub assessment: RecoveryAssessment,
}

/// Configuration for the deleted file scanner.
#[derive(Clone, Copy, Debug)]
pub struct DeletedFileScanConfig {
    /// Plausible NTFS timestamp range for recovered records.
    pub timestamp_bounds: TimestampBounds,
    /// Skip MFT records 0-23 (system metafiles). Default: `true`.
    pub skip_system_records: bool,
    /// Only return deleted files, not directories. Default: `false`.
    pub skip_directories: bool,
}

impl Default for DeletedFileScanConfig {
    fn default() -> Self {
        Self {
            timestamp_bounds: TimestampBounds::default(),
            skip_system_records: true,
            skip_directories: false,
        }
    }
}

/// Iterator that scans the MFT for deleted file records.
///
/// Created via [`Ntfs::deleted_files`] or
/// [`NtfsDeletedFileScanner::new`].
pub struct NtfsDeletedFileScanner {
    mft_entries: NtfsMftEntries,
    bitmap: NtfsClusterBitmap,
    config: DeletedFileScanConfig,
    cluster_size: u32,
}

impl NtfsDeletedFileScanner {
    /// Create a scanner with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the MFT or cluster bitmap cannot be opened.
    pub fn new<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: crate::io::Read + crate::io::Seek,
    {
        Self::with_config(ntfs, fs, DeletedFileScanConfig::default())
    }

    /// Create a scanner with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the MFT or cluster bitmap cannot be opened.
    pub fn with_config<T>(ntfs: &Ntfs, fs: &mut T, config: DeletedFileScanConfig) -> Result<Self>
    where
        T: crate::io::Read + crate::io::Seek,
    {
        let mft_entries = ntfs.mft_entries(fs)?;
        let bitmap = ntfs.cluster_bitmap(fs)?;
        let cluster_size = ntfs.cluster_size();
        Ok(Self {
            mft_entries,
            bitmap,
            config,
            cluster_size,
        })
    }

    /// Builds a scanner directly from its parts for unit tests, bypassing
    /// the MFT/bitmap metafile lookups in [`NtfsDeletedFileScanner::new`].
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        mft_entries: NtfsMftEntries,
        bitmap: NtfsClusterBitmap,
        config: DeletedFileScanConfig,
        cluster_size: u32,
    ) -> Self {
        Self {
            mft_entries,
            bitmap,
            config,
            cluster_size,
        }
    }

    /// Check if all timestamps fall within the configured plausible range.
    fn timestamps_plausible(&self, timestamps: &[NtfsTime]) -> bool {
        self.config.timestamp_bounds.all_plausible(timestamps)
    }

    /// Extract data runs from a file's `$DATA` attribute and check
    /// each against the cluster bitmap.
    ///
    /// Only reads runs from the first `$DATA` attribute record. Files
    /// with attribute lists spanning multiple MFT records will have
    /// incomplete run data — acceptable for deleted file recovery where
    /// connected attributes may already be overwritten.
    fn extract_data_runs<T>(
        &mut self,
        file: &crate::file::NtfsFile<'_>,
        fs: &mut T,
    ) -> (Vec<DeletedDataRun>, u64, bool, bool)
    where
        T: crate::io::Read + crate::io::Seek,
    {
        let Some(Ok(data_item)) = file.data(fs, "") else {
            return (Vec::new(), 0, false, false);
        };

        let Ok(attr) = data_item.to_attribute() else {
            return (Vec::new(), 0, false, false);
        };

        let logical_size = attr.value_length();

        if attr.is_resident() {
            return (Vec::new(), logical_size, false, false);
        }

        let Ok(non_resident) = attr.non_resident_value() else {
            return (Vec::new(), logical_size, false, false);
        };

        let mut runs = Vec::new();
        let mut all_free = true;

        for run_result in non_resident.data_runs() {
            let Ok(run) = run_result else {
                // NtfsDataRuns does not advance on error, so
                // continuing would loop forever on corrupt runs.
                break;
            };

            let pos = run.data_position();
            let Some(byte_offset) = pos.value().map(core::num::NonZero::get) else {
                // Sparse run — cannot verify allocation status
                all_free = false;
                runs.push(DeletedDataRun {
                    cluster_offset: 0,
                    cluster_count: run.allocated_size() / u64::from(self.cluster_size),
                    status: ClusterStatus::Unknown,
                });
                continue;
            };

            let cluster_offset = byte_offset / u64::from(self.cluster_size);
            let cluster_count = run.allocated_size() / u64::from(self.cluster_size);

            let status =
                if let Ok(range) = self.bitmap.range_status(fs, cluster_offset, cluster_count) {
                    if range.free == cluster_count {
                        ClusterStatus::AllFree
                    } else if range.allocated == cluster_count {
                        all_free = false;
                        ClusterStatus::AllAllocated
                    } else {
                        all_free = false;
                        ClusterStatus::Mixed
                    }
                } else {
                    all_free = false;
                    ClusterStatus::Unknown
                };

            runs.push(DeletedDataRun {
                cluster_offset,
                cluster_count,
                status,
            });
        }

        let has_runs = !runs.is_empty();
        if !has_runs {
            all_free = false;
        }
        (runs, logical_size, has_runs, all_free)
    }

    /// Advance to the next deleted file record.
    ///
    /// Returns `None` when the MFT is exhausted.
    pub fn next<T>(&mut self, ntfs: &Ntfs, fs: &mut T) -> Option<Result<NtfsDeletedFile>>
    where
        T: crate::io::Read + crate::io::Seek,
    {
        loop {
            let file = match self.mft_entries.next(ntfs, fs)? {
                Ok(f) => f,
                Err(e) => return Some(Err(e)),
            };

            let record_number = file.file_record_number();

            let flags = file.flags();
            if flags.contains(NtfsFileFlags::IN_USE) {
                continue;
            }

            if self.config.skip_system_records && record_number < SYSTEM_RECORD_COUNT {
                continue;
            }

            let is_directory = flags.contains(NtfsFileFlags::IS_DIRECTORY);

            if self.config.skip_directories && is_directory {
                continue;
            }

            let sequence_number = file.sequence_number();

            // Use name_pair() to prefer Win32/Posix names over DOS 8.3
            let (name, parent_record_number, fn_data_size, name_parse_failed) =
                match file.name_pair(fs, None) {
                    Some(Ok(pair)) => {
                        let n = pair.primary.name().to_string_lossy();
                        let parent = pair
                            .primary
                            .parent_directory_reference()
                            .file_record_number();
                        let size = pair.primary.data_size();
                        (Some(n), Some(parent), size, false)
                    }
                    Some(Err(_)) => (None, None, 0, true),
                    None => (None, None, 0, false),
                };

            let (created, modified, accessed, mft_modified, ts_list, info_parse_failed) =
                match file.info() {
                    Ok(info) => {
                        let c = info.creation_time();
                        let m = info.modification_time();
                        let a = info.access_time();
                        let mm = info.mft_record_modification_time();
                        (
                            Some(c),
                            Some(m),
                            Some(a),
                            Some(mm),
                            alloc::vec![c, m, a, mm],
                            false,
                        )
                    }
                    Err(_) => (None, None, None, None, Vec::new(), true),
                };

            let attributes_parseable = name.is_some() || created.is_some();

            let (data_runs, data_logical_size, data_runs_present, clusters_free) =
                self.extract_data_runs(&file, fs);

            let logical_size = if data_logical_size > 0 {
                data_logical_size
            } else {
                fn_data_size
            };

            let has_fn_size = name.is_some();
            let has_data_size = data_runs_present || data_logical_size > 0;
            let sizes_consistent = match (has_fn_size, has_data_size) {
                (true, true) => fn_data_size == data_logical_size,
                (true, false) | (false, true) => true,
                (false, false) => false,
            };

            let mut checks = RecoveryChecks::VALID_SIGNATURE;
            checks.set(RecoveryChecks::ATTRIBUTES_PARSEABLE, attributes_parseable);
            checks.set(RecoveryChecks::NAME_RECOVERED, name.is_some());
            checks.set(
                RecoveryChecks::TIMESTAMPS_PLAUSIBLE,
                self.timestamps_plausible(&ts_list),
            );
            checks.set(RecoveryChecks::DATA_RUNS_PRESENT, data_runs_present);
            checks.set(RecoveryChecks::CLUSTERS_FREE, clusters_free);
            checks.set(RecoveryChecks::SIZES_CONSISTENT, sizes_consistent);
            checks.set(RecoveryChecks::NAME_PARSE_FAILED, name_parse_failed);
            checks.set(RecoveryChecks::INFO_PARSE_FAILED, info_parse_failed);
            let assessment = RecoveryAssessment { checks };

            return Some(Ok(NtfsDeletedFile {
                record_number,
                sequence_number,
                is_directory,
                name,
                parent_record_number,
                created,
                modified,
                accessed,
                mft_modified,
                logical_size,
                data_runs,
                assessment,
            }));
        }
    }
}

#[cfg(test)]
#[path = "deleted_files_tests/mod.rs"]
mod tests;
