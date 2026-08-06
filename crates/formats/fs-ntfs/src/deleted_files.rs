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

/// Heuristic assessment of how recoverable a deleted file is.
///
/// Each field represents one validation check. Use [`score`] for a
/// combined 0-7 numeric score or [`fully_recoverable`] to check if
/// all checks pass.
///
/// [`score`]: RecoveryAssessment::score
/// [`fully_recoverable`]: RecoveryAssessment::fully_recoverable
#[derive(Clone, Debug)]
pub struct RecoveryAssessment {
    /// The MFT record had a valid `FILE` signature after USA fixup.
    pub valid_signature: bool,
    /// At least one attribute was parsed without error.
    pub attributes_parseable: bool,
    /// A `$FILE_NAME` attribute was found with a non-empty name.
    pub name_recovered: bool,
    /// All recovered timestamps fall within the configured plausible
    /// range.
    pub timestamps_plausible: bool,
    /// The `$DATA` attribute contains non-resident data runs.
    pub data_runs_present: bool,
    /// All data run clusters are still unallocated.
    pub clusters_free: bool,
    /// The logical file size from `$FILE_NAME` is consistent with the
    /// `$DATA` attribute length.
    pub sizes_consistent: bool,
    /// The `$FILE_NAME` attribute existed but could not be parsed.
    pub name_parse_failed: bool,
    /// The `$STANDARD_INFORMATION` attribute existed but could not be
    /// parsed.
    pub info_parse_failed: bool,
}

impl RecoveryAssessment {
    /// Combined score from 0 (no checks pass) to 7 (all checks pass).
    pub fn score(&self) -> u8 {
        self.valid_signature as u8
            + self.attributes_parseable as u8
            + self.name_recovered as u8
            + self.timestamps_plausible as u8
            + self.data_runs_present as u8
            + self.clusters_free as u8
            + self.sizes_consistent as u8
    }

    /// Returns `true` if every check passes.
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
    pub fn new<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: crate::io::Read + crate::io::Seek,
    {
        Self::with_config(ntfs, fs, DeletedFileScanConfig::default())
    }

    /// Create a scanner with custom configuration.
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
        let data_item = match file.data(fs, "") {
            Some(Ok(item)) => item,
            _ => return (Vec::new(), 0, false, false),
        };

        let attr = match data_item.to_attribute() {
            Ok(a) => a,
            Err(_) => return (Vec::new(), 0, false, false),
        };

        let logical_size = attr.value_length();

        if attr.is_resident() {
            return (Vec::new(), logical_size, false, false);
        }

        let non_resident = match attr.non_resident_value() {
            Ok(v) => v,
            Err(_) => return (Vec::new(), logical_size, false, false),
        };

        let mut runs = Vec::new();
        let mut all_free = true;

        for run_result in non_resident.data_runs() {
            let run = match run_result {
                Ok(r) => r,
                // NtfsDataRuns does not advance on error, so
                // continuing would loop forever on corrupt runs.
                Err(_) => break,
            };

            let pos = run.data_position();
            if pos.value().is_none() {
                // Sparse run — cannot verify allocation status
                all_free = false;
                runs.push(DeletedDataRun {
                    cluster_offset: 0,
                    cluster_count: run.allocated_size() / u64::from(self.cluster_size),
                    status: ClusterStatus::Unknown,
                });
                continue;
            }

            let byte_offset = pos.value().expect("checked above").get();
            let cluster_offset = byte_offset / u64::from(self.cluster_size);
            let cluster_count = run.allocated_size() / u64::from(self.cluster_size);

            let status = match self.bitmap.range_status(fs, cluster_offset, cluster_count) {
                Ok(range) => {
                    if range.free == cluster_count {
                        ClusterStatus::AllFree
                    } else if range.allocated == cluster_count {
                        all_free = false;
                        ClusterStatus::AllAllocated
                    } else {
                        all_free = false;
                        ClusterStatus::Mixed
                    }
                }
                Err(_) => {
                    all_free = false;
                    ClusterStatus::Unknown
                }
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

            let assessment = RecoveryAssessment {
                valid_signature: true,
                attributes_parseable,
                name_recovered: name.is_some(),
                timestamps_plausible: self.timestamps_plausible(&ts_list),
                data_runs_present,
                clusters_free,
                sizes_consistent,
                name_parse_failed,
                info_parse_failed,
            };

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
mod tests {
    use super::*;
    use crate::attribute::NtfsAttributeType;
    use crate::data_run_map::DataRunMap;
    use crate::time::NTFS_TIMESTAMP_1997;
    use std::io::Cursor;

    const FRS: u32 = 1024; // file record size
    const CLUSTER: u32 = 512; // cluster size
    const MFT_START: u64 = 8192; // physical byte offset of MFT record 0
    const BITMAP_START: u64 = 4096; // physical byte offset of bitmap data

    /// A plausible NTFS timestamp inside the default 1997..2030 bounds.
    const GOOD_TIME: u64 = NTFS_TIMESTAMP_1997 + 1_000_000;

    fn make_boot_sector() -> [u8; 512] {
        let mut bs = [0u8; 512];
        bs[3..11].copy_from_slice(b"NTFS    ");
        bs[0x0B..0x0D].copy_from_slice(&(CLUSTER as u16).to_le_bytes());
        bs[0x0D] = 1; // sectors_per_cluster
        bs[0x28..0x30].copy_from_slice(&65536u64.to_le_bytes()); // total_sectors
        bs[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
        bs[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
        bs[0x40] = 0xF6; // -10 => 1024-byte records
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    /// Resident `$STANDARD_INFORMATION` (48-byte value) with all four
    /// timestamps set to `time`.
    fn si_attribute(time: u64) -> Vec<u8> {
        let mut value = [0u8; 48];
        value[0..8].copy_from_slice(&time.to_le_bytes()); // creation
        value[8..16].copy_from_slice(&time.to_le_bytes()); // modification
        value[16..24].copy_from_slice(&time.to_le_bytes()); // mft modification
        value[24..32].copy_from_slice(&time.to_le_bytes()); // access
        resident_attribute(NtfsAttributeType::StandardInformation, &value)
    }

    /// Resident `$FILE_NAME` attribute (Win32AndDos namespace) naming the
    /// file `name`, parented to `parent`, reporting logical size `data_size`.
    fn fn_attribute(name: &str, parent: u64, data_size: u64) -> Vec<u8> {
        let chars: Vec<u16> = name.encode_utf16().collect();
        let mut value = vec![0u8; 66 + chars.len() * 2];
        value[0..8].copy_from_slice(&parent.to_le_bytes()); // parent reference
        value[8..16].copy_from_slice(&GOOD_TIME.to_le_bytes()); // creation
        value[16..24].copy_from_slice(&GOOD_TIME.to_le_bytes()); // modification
        value[24..32].copy_from_slice(&GOOD_TIME.to_le_bytes()); // mft modification
        value[32..40].copy_from_slice(&GOOD_TIME.to_le_bytes()); // access
        value[40..48].copy_from_slice(&data_size.to_le_bytes()); // allocated_size
        value[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
        value[64] = chars.len() as u8; // name_length (chars)
        value[65] = 3; // namespace = Win32AndDos
        for (i, c) in chars.iter().enumerate() {
            value[66 + i * 2..66 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        resident_attribute(NtfsAttributeType::FileName, &value)
    }

    /// Resident attribute (no name) of `ty` carrying `value`.
    fn resident_attribute(ty: NtfsAttributeType, value: &[u8]) -> Vec<u8> {
        let value_offset = 24usize;
        let attribute_length = value_offset + value.len();
        let mut attr = vec![0u8; attribute_length];
        attr[0..4].copy_from_slice(&(ty as u32).to_le_bytes());
        attr[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());
        attr[8] = 0; // resident
        attr[14..16].copy_from_slice(&1u16.to_le_bytes()); // instance
        attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes()); // value_length
        attr[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes()); // value_offset
        attr[value_offset..attribute_length].copy_from_slice(value);
        attr
    }

    /// Non-resident `$DATA` attribute holding `runs`, with `data_size`.
    fn data_attribute_non_resident(runs: &[u8], data_size: u64) -> Vec<u8> {
        let data_runs_offset = 64usize;
        let attribute_length = data_runs_offset + runs.len();
        let mut attr = vec![0u8; attribute_length];
        attr[0..4].copy_from_slice(&(NtfsAttributeType::Data as u32).to_le_bytes());
        attr[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());
        attr[8] = 1; // non-resident
        attr[14..16].copy_from_slice(&2u16.to_le_bytes()); // instance
        attr[32..34].copy_from_slice(&(data_runs_offset as u16).to_le_bytes()); // data_runs_offset
        attr[40..48].copy_from_slice(&data_size.to_le_bytes()); // allocated_size
        attr[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
        attr[56..64].copy_from_slice(&data_size.to_le_bytes()); // initialized_size
        attr[data_runs_offset..attribute_length].copy_from_slice(runs);
        attr
    }

    /// Resident `$DATA` attribute (in-MFT data) of length `value.len()`.
    fn data_attribute_resident(value: &[u8]) -> Vec<u8> {
        resident_attribute(NtfsAttributeType::Data, value)
    }

    /// Builds a 1 KiB FILE record from a list of attribute byte blobs and
    /// the given `flags`. Applies the update-sequence fixup.
    fn make_file_record(flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut rec = vec![0u8; FRS as usize];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        let usn = 0x0001u16;
        rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes());
        rec[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes());
        rec[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes());
        rec[510..512].copy_from_slice(&usn.to_le_bytes());
        rec[1022..1024].copy_from_slice(&usn.to_le_bytes());
        rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
        rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
        rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first_attribute_offset
        rec[22..24].copy_from_slice(&flags.to_le_bytes());
        rec[24..28].copy_from_slice(&FRS.to_le_bytes()); // data_size
        rec[28..32].copy_from_slice(&FRS.to_le_bytes()); // allocated_size

        let mut pos = 56usize;
        for attr in attributes {
            rec[pos..pos + attr.len()].copy_from_slice(attr);
            pos += attr.len();
        }
        rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // End marker
        rec
    }

    /// Single-run data: header byte 0x21 (1 length byte, 1 offset byte),
    /// `clusters` length, LCN offset `lcn`, terminator.
    fn one_data_run(clusters: u8, lcn: u8) -> [u8; 4] {
        [0x21, clusters, lcn, 0x00]
    }

    /// Single SPARSE run: header byte 0x01 (1 length byte, 0 offset bytes
    /// => VCN 0 => sparse), `clusters` length, terminator.
    fn one_sparse_run(clusters: u8) -> [u8; 3] {
        [0x01, clusters, 0x00]
    }

    /// Assembles an image and a scanner over `records` (record N at
    /// `MFT_START + N*FRS`). `bitmap_bytes` seeds the bitmap region (bit
    /// per cluster). `config` controls scanning behaviour.
    fn build_scanner(
        records: &[Vec<u8>],
        bitmap_bytes: &[u8],
        config: DeletedFileScanConfig,
    ) -> (NtfsDeletedFileScanner, Ntfs, Cursor<Vec<u8>>) {
        let count = records.len() as u64;
        let region_len = count * FRS as u64;
        let total_len = (MFT_START + region_len) as usize;
        let mut data = vec![0u8; total_len.max((BITMAP_START as usize) + CLUSTER as usize)];
        data[0..512].copy_from_slice(&make_boot_sector());
        for (i, rec) in records.iter().enumerate() {
            let off = MFT_START as usize + i * FRS as usize;
            data[off..off + FRS as usize].copy_from_slice(rec);
        }
        // Seed the bitmap region.
        let bm_off = BITMAP_START as usize;
        data[bm_off..bm_off + bitmap_bytes.len()].copy_from_slice(bitmap_bytes);

        let mut fs = Cursor::new(data);
        let ntfs = Ntfs::new(&mut fs).unwrap();

        let mft_map = DataRunMap::from_segments_for_test(&[(Some(MFT_START), region_len)]);
        let mft_entries = NtfsMftEntries::from_parts_for_test(mft_map, count, FRS);

        let bitmap_map =
            DataRunMap::from_segments_for_test(&[(Some(BITMAP_START), CLUSTER as u64)]);
        let bitmap =
            NtfsClusterBitmap::from_parts_for_test(bitmap_map, CLUSTER as u64 * 8, CLUSTER);

        let scanner =
            NtfsDeletedFileScanner::from_parts_for_test(mft_entries, bitmap, config, CLUSTER);
        (scanner, ntfs, fs)
    }

    fn config_keep_system() -> DeletedFileScanConfig {
        DeletedFileScanConfig {
            skip_system_records: false,
            skip_directories: false,
            ..DeletedFileScanConfig::default()
        }
    }

    #[test]
    fn synthetic_timestamps_plausible_delegates() {
        let (scanner, _ntfs, _fs) = build_scanner(
            &[make_file_record(0, &[])],
            &[0u8; 16],
            config_keep_system(),
        );
        // In-range timestamps are plausible; an out-of-range one is not
        // (line 205 returns the genuine bool, not true/false constants).
        // Note: an empty set and a far-future timestamp are both
        // implausible, while a non-zero in-range value is plausible.
        assert!(scanner.timestamps_plausible(&[NtfsTime::from(GOOD_TIME)]));
        assert!(!scanner.timestamps_plausible(&[NtfsTime::from(u64::MAX)]));
        assert!(!scanner.timestamps_plausible(&[]));
    }

    #[test]
    fn synthetic_next_returns_none_when_exhausted() {
        // Single in-use record: skipped, so next yields None (line 310).
        let rec = make_file_record(NtfsFileFlags::IN_USE.bits(), &[]);
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());
        assert!(scanner.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_next_skips_in_use_records() {
        // First record in use (skipped via line 319), second deleted and
        // returned.
        let in_use = make_file_record(
            NtfsFileFlags::IN_USE.bits(),
            &[si_attribute(GOOD_TIME), fn_attribute("live.txt", 5, 0)],
        );
        let deleted = make_file_record(
            0,
            &[si_attribute(GOOD_TIME), fn_attribute("gone.txt", 5, 0)],
        );
        let (mut scanner, ntfs, mut fs) =
            build_scanner(&[in_use, deleted], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.record_number, 1);
        assert_eq!(result.name.as_deref(), Some("gone.txt"));
        assert!(scanner.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_skip_system_records_boundary() {
        // 25 records (0..=24); only record 24 is non-system. With
        // skip_system_records, records 0..24 are skipped (line 323 `<`),
        // leaving record 24 (== SYSTEM_RECORD_COUNT, not skipped).
        let mut records = Vec::new();
        for _ in 0..SYSTEM_RECORD_COUNT + 1 {
            records.push(make_file_record(
                0,
                &[si_attribute(GOOD_TIME), fn_attribute("f.txt", 5, 0)],
            ));
        }
        let config = DeletedFileScanConfig {
            skip_system_records: true,
            skip_directories: false,
            ..DeletedFileScanConfig::default()
        };
        let (mut scanner, ntfs, mut fs) = build_scanner(&records, &[0u8; 16], config);

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.record_number, SYSTEM_RECORD_COUNT);
        assert!(scanner.next(&ntfs, &mut fs).is_none());
    }

    #[test]
    fn synthetic_skip_directories() {
        // A deleted directory is skipped when skip_directories is set
        // (line 329), but returned otherwise.
        let dir = make_file_record(
            NtfsFileFlags::IS_DIRECTORY.bits(),
            &[si_attribute(GOOD_TIME), fn_attribute("adir", 5, 0)],
        );

        let config_skip = DeletedFileScanConfig {
            skip_system_records: false,
            skip_directories: true,
            ..DeletedFileScanConfig::default()
        };
        let (mut scanner, ntfs, mut fs) =
            build_scanner(std::slice::from_ref(&dir), &[0u8; 16], config_skip);
        assert!(scanner.next(&ntfs, &mut fs).is_none());

        let (mut scanner, ntfs, mut fs) = build_scanner(&[dir], &[0u8; 16], config_keep_system());
        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert!(result.is_directory);
    }

    #[test]
    fn synthetic_extract_data_runs_all_free() {
        // A deleted file with a non-resident $DATA run over 5 clusters that
        // are all unallocated (bitmap all zero). extract_data_runs reports
        // the run with AllFree, clusters_free=true, data_runs_present=true.
        let runs = one_data_run(5, 2); // 5 clusters at LCN 2
        let data_size = 5 * CLUSTER as u64;
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("d.bin", 5, data_size),
                data_attribute_non_resident(&runs, data_size),
            ],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.data_runs.len(), 1);
        let run = &result.data_runs[0];
        // cluster_offset = byte_offset / cluster_size (line 268); LCN 2 *
        // 512 / 512 = 2.
        assert_eq!(run.cluster_offset, 2);
        // cluster_count = allocated_size / cluster_size (line 269) = 5.
        assert_eq!(run.cluster_count, 5);
        assert_eq!(run.status, ClusterStatus::AllFree);
        assert!(result.assessment.data_runs_present);
        assert!(result.assessment.clusters_free);
        // logical_size comes from $DATA (line 375 `>`).
        assert_eq!(result.logical_size, data_size);
    }

    #[test]
    fn synthetic_extract_data_runs_all_allocated() {
        // Same run but every cluster is allocated => AllAllocated and
        // clusters_free=false (lines 273/275 `==`).
        let runs = one_data_run(5, 2);
        let data_size = 5 * CLUSTER as u64;
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("d.bin", 5, data_size),
                data_attribute_non_resident(&runs, data_size),
            ],
        );
        // Mark clusters 2..7 allocated (bits 2..6 of byte 0).
        let bitmap = [0b1111_1100u8; 16];
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &bitmap, config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.data_runs[0].status, ClusterStatus::AllAllocated);
        assert!(!result.assessment.clusters_free);
    }

    #[test]
    fn synthetic_extract_data_runs_mixed() {
        // Some clusters allocated, some free => Mixed (lines 273/275 both
        // false).
        let runs = one_data_run(4, 2); // clusters 2,3,4,5
        let data_size = 4 * CLUSTER as u64;
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("d.bin", 5, data_size),
                data_attribute_non_resident(&runs, data_size),
            ],
        );
        // Allocate cluster 2 only (bit 2 of byte 0).
        let bitmap = [0b0000_0100u8; 16];
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &bitmap, config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.data_runs[0].status, ClusterStatus::Mixed);
        assert!(!result.assessment.clusters_free);
    }

    #[test]
    fn synthetic_resident_data_has_no_runs() {
        // A deleted file with resident $DATA: no data runs present
        // (line 296/297 set all_free=false because runs is empty), but a
        // non-zero logical size from the resident value.
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("small.txt", 5, 4),
                data_attribute_resident(b"data"),
            ],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert!(result.data_runs.is_empty());
        assert!(!result.assessment.data_runs_present);
        assert!(!result.assessment.clusters_free);
        // sizes_consistent: fn_data_size (4) == data_logical_size (4) => true
        // (line 384 `==`).
        assert!(result.assessment.sizes_consistent);
        assert_eq!(result.logical_size, 4);
    }

    #[test]
    fn synthetic_sizes_inconsistent_when_fn_and_data_disagree() {
        // $FILE_NAME reports data_size 99 but resident $DATA is 4 bytes:
        // sizes_consistent is false (line 384 `==`).
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("x.txt", 5, 99),
                data_attribute_resident(b"data"),
            ],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert!(!result.assessment.sizes_consistent);
    }

    #[test]
    fn synthetic_attributes_parseable_from_name_only() {
        // A deleted record with a $FILE_NAME but no $STANDARD_INFORMATION:
        // attributes_parseable is true because name.is_some() (line 370
        // `||`), and timestamps_plausible reflects the empty timestamp set.
        let rec = make_file_record(0, &[fn_attribute("named.txt", 5, 0)]);
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert!(result.assessment.attributes_parseable);
        assert!(result.assessment.name_recovered);
        assert_eq!(result.name.as_deref(), Some("named.txt"));
        assert!(result.created.is_none());
    }

    #[test]
    fn synthetic_extract_data_runs_sparse() {
        // A sparse $DATA run: status Unknown, cluster_count derived from the
        // sparse branch `allocated_size / cluster_size` (line 278). 3 sparse
        // clusters => allocated_size 1536, cluster_count 1536/512 = 3.
        let runs = one_sparse_run(3);
        let data_size = 3 * CLUSTER as u64;
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("s.bin", 5, data_size),
                data_attribute_non_resident(&runs, data_size),
            ],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.data_runs.len(), 1);
        let run = &result.data_runs[0];
        assert_eq!(run.status, ClusterStatus::Unknown);
        assert_eq!(run.cluster_offset, 0);
        assert_eq!(run.cluster_count, 3);
        // A sparse run cannot be confirmed free.
        assert!(!result.assessment.clusters_free);
    }

    #[test]
    fn synthetic_logical_size_prefers_data_over_fn() {
        // data_logical_size > 0 (line 392 `>`): logical_size uses the $DATA
        // size, not the (different) $FILE_NAME size. With data_size 2560 and
        // fn_data_size 1234, a `<`/`==` mutation of the comparison would
        // select fn_data_size instead.
        let runs = one_data_run(5, 2);
        let data_size = 5 * CLUSTER as u64; // 2560
        let rec = make_file_record(
            0,
            &[
                si_attribute(GOOD_TIME),
                fn_attribute("d.bin", 5, 1234),
                data_attribute_non_resident(&runs, data_size),
            ],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.logical_size, data_size);
    }

    #[test]
    fn synthetic_logical_size_falls_back_to_fn_when_data_zero() {
        // data_logical_size == 0 (no $DATA attribute) and a non-zero
        // $FILE_NAME size: `data_logical_size > 0` is false (line 392), so
        // logical_size falls back to the $FILE_NAME size. A `>=`/`==`
        // mutation would (wrongly) pick the zero $DATA size. The same flag
        // drives `has_data_size` (line 399 `>`): with no data runs and a
        // name, `(has_fn_size, has_data_size) == (true, false)` makes
        // sizes_consistent true; a `>=` mutation would force a (true,true)
        // mismatch check that fails.
        let rec = make_file_record(
            0,
            &[si_attribute(GOOD_TIME), fn_attribute("n.txt", 5, 4321)],
        );
        let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

        let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
        assert_eq!(result.logical_size, 4321);
        assert!(!result.assessment.data_runs_present);
        assert!(result.assessment.sizes_consistent);
    }

    fn all_pass() -> RecoveryAssessment {
        RecoveryAssessment {
            valid_signature: true,
            attributes_parseable: true,
            name_recovered: true,
            timestamps_plausible: true,
            data_runs_present: true,
            clusters_free: true,
            sizes_consistent: true,
            name_parse_failed: false,
            info_parse_failed: false,
        }
    }

    fn all_fail() -> RecoveryAssessment {
        RecoveryAssessment {
            valid_signature: false,
            attributes_parseable: false,
            name_recovered: false,
            timestamps_plausible: false,
            data_runs_present: false,
            clusters_free: false,
            sizes_consistent: false,
            name_parse_failed: false,
            info_parse_failed: false,
        }
    }

    #[test]
    fn test_recovery_assessment_all_pass() {
        let a = all_pass();
        assert_eq!(a.score(), 7);
        assert!(a.fully_recoverable());
    }

    #[test]
    fn test_recovery_assessment_all_fail() {
        let a = all_fail();
        assert_eq!(a.score(), 0);
        assert!(!a.fully_recoverable());
    }

    #[test]
    fn test_recovery_assessment_partial() {
        let a = RecoveryAssessment {
            valid_signature: true,
            attributes_parseable: true,
            name_recovered: true,
            timestamps_plausible: false,
            data_runs_present: false,
            clusters_free: false,
            sizes_consistent: false,
            name_parse_failed: false,
            info_parse_failed: false,
        };
        assert_eq!(a.score(), 3);
        assert!(!a.fully_recoverable());
    }

    #[test]
    fn test_config_defaults() {
        let config = DeletedFileScanConfig::default();
        assert!(config.skip_system_records);
        assert!(!config.skip_directories);
        assert!(config.timestamp_bounds.min > 0);
        assert!(config.timestamp_bounds.max > config.timestamp_bounds.min);
    }

    #[test]
    fn test_cluster_status_variants_are_distinct() {
        assert_ne!(ClusterStatus::AllFree, ClusterStatus::AllAllocated);
        assert_ne!(ClusterStatus::AllFree, ClusterStatus::Mixed);
        assert_ne!(ClusterStatus::AllFree, ClusterStatus::Unknown);
    }

    #[test]
    fn test_recovery_assessment_one_field_at_a_time() {
        let base = all_fail();
        assert_eq!(base.score(), 0);

        let fields = [
            RecoveryAssessment {
                valid_signature: true,
                ..base.clone()
            },
            RecoveryAssessment {
                attributes_parseable: true,
                ..base.clone()
            },
            RecoveryAssessment {
                name_recovered: true,
                ..base.clone()
            },
            RecoveryAssessment {
                timestamps_plausible: true,
                ..base.clone()
            },
            RecoveryAssessment {
                data_runs_present: true,
                ..base.clone()
            },
            RecoveryAssessment {
                clusters_free: true,
                ..base.clone()
            },
            RecoveryAssessment {
                sizes_consistent: true,
                ..base
            },
        ];

        for (i, field) in fields.iter().enumerate() {
            assert_eq!(
                field.score(),
                1,
                "field index {i} should contribute 1 to score",
            );
        }
    }

    #[test]
    fn test_deleted_data_run_debug_format() {
        let run = DeletedDataRun {
            cluster_offset: 1000,
            cluster_count: 50,
            status: ClusterStatus::AllFree,
        };
        let debug = alloc::format!("{run:?}");
        assert!(debug.contains("1000"));
        assert!(debug.contains("50"));
        assert!(debug.contains("AllFree"));
    }

    #[test]
    fn test_deleted_file_default_state() {
        let file = NtfsDeletedFile {
            record_number: 42,
            sequence_number: 3,
            is_directory: false,
            name: None,
            parent_record_number: None,
            created: None,
            modified: None,
            accessed: None,
            mft_modified: None,
            logical_size: 0,
            data_runs: Vec::new(),
            assessment: RecoveryAssessment {
                valid_signature: true,
                attributes_parseable: false,
                name_recovered: false,
                timestamps_plausible: false,
                data_runs_present: false,
                clusters_free: false,
                sizes_consistent: false,
                name_parse_failed: false,
                info_parse_failed: false,
            },
        };
        assert_eq!(file.record_number, 42);
        assert_eq!(file.sequence_number, 3);
        assert!(!file.is_directory);
        assert!(file.name.is_none());
        assert_eq!(file.assessment.score(), 1);
    }

    mod integration {
        use super::*;

        #[test]
        fn test_scanner_construction() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let scanner = NtfsDeletedFileScanner::new(&ntfs, &mut testfs1);
            assert!(scanner.is_ok());
        }

        #[test]
        fn test_scanner_custom_config() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let config = DeletedFileScanConfig {
                skip_system_records: false,
                skip_directories: true,
                ..DeletedFileScanConfig::default()
            };
            let scanner = NtfsDeletedFileScanner::with_config(&ntfs, &mut testfs1, config);
            assert!(scanner.is_ok());
        }

        #[test]
        fn test_scanner_runs_to_completion() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let mut scanner = ntfs
                .deleted_files(&mut testfs1)
                .expect("scanner construction");
            let mut count = 0u64;
            while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
                match result {
                    Ok(deleted) => {
                        count += 1;
                        assert!(
                            deleted.assessment.score() >= 1,
                            "record {} has score 0",
                            deleted.record_number,
                        );
                    }
                    Err(e) => panic!("scanner error: {e}"),
                }
            }
            eprintln!("Found {count} deleted file records");
        }

        #[test]
        fn test_scanner_skips_in_use_records() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let mut scanner = ntfs
                .deleted_files(&mut testfs1)
                .expect("scanner construction");
            while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
                let deleted = result.expect("scan error");
                assert_ne!(
                    deleted.record_number, 5,
                    "in-use root directory record yielded"
                );
            }
        }

        #[test]
        fn test_scanner_skips_system_records_by_default() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let mut scanner = ntfs
                .deleted_files(&mut testfs1)
                .expect("scanner construction");
            while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
                let deleted = result.expect("scan error");
                assert!(
                    deleted.record_number >= SYSTEM_RECORD_COUNT,
                    "system record {} not skipped",
                    deleted.record_number,
                );
            }
        }

        #[test]
        fn test_deleted_file_metadata_populated() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let mut scanner = ntfs
                .deleted_files(&mut testfs1)
                .expect("scanner construction");
            if let Some(Ok(deleted)) = scanner.next(&ntfs, &mut testfs1) {
                assert!(deleted.sequence_number > 0 || deleted.record_number > 0);
            }
        }

        #[test]
        fn test_scanner_includes_system_records_when_configured() {
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let config = DeletedFileScanConfig {
                skip_system_records: false,
                ..DeletedFileScanConfig::default()
            };
            let mut scanner = NtfsDeletedFileScanner::with_config(&ntfs, &mut testfs1, config)
                .expect("scanner construction");

            let mut has_system = false;
            while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
                if let Ok(deleted) = result
                    && deleted.record_number < SYSTEM_RECORD_COUNT
                {
                    has_system = true;
                    break;
                }
            }
            assert!(
                has_system,
                "expected at least one unused system record in testfs1"
            );
        }

        #[test]
        fn test_scanner_propagates_mft_parse_errors() {
            use crate::error::NtfsError;

            // Load test filesystem into a mutable buffer.
            let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
                return;
            };
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let file_record_size = ntfs.file_record_size() as usize;

            // Build a DataRunMap for fragmentation-safe offset resolution.
            let mft_file = ntfs.file(&mut testfs1, 0).unwrap();
            let mft_data_item = mft_file.data(&mut testfs1, "").unwrap().unwrap();
            let mft_attr = mft_data_item.to_attribute().unwrap();
            let nrv = mft_attr.non_resident_value().unwrap();
            let map = crate::data_run_map::DataRunMap::from_data_runs(nrv.data_runs()).unwrap();

            // Find a non-in-use record beyond system range (record >= 24)
            // by scanning the clean image first.
            let mut iter = ntfs.mft_entries(&mut testfs1).unwrap();
            let total = iter.total_records();
            let mut target_record = None;
            for record_num in SYSTEM_RECORD_COUNT..total {
                iter.seek_to_record(record_num);
                if let Some(Ok(file)) = iter.next(&ntfs, &mut testfs1)
                    && !file.flags().contains(crate::file::NtfsFileFlags::IN_USE)
                {
                    target_record = Some(record_num);
                    break;
                }
            }

            // If no deleted record found, we can still corrupt any non-system
            // record. The scanner will encounter the error regardless.
            let corrupt_record = target_record.unwrap_or(SYSTEM_RECORD_COUNT);

            // Resolve physical offset via DataRunMap (handles fragmented MFTs).
            let logical_offset = corrupt_record * file_record_size as u64;
            let (pos, _) = map.resolve_position(logical_offset).unwrap();
            let offset = pos.value().unwrap().get();
            let buf = testfs1.get_mut();
            buf[offset as usize..offset as usize + 4].copy_from_slice(&[0xDE, 0xAD, 0x00, 0x00]);

            // Re-parse and scan — the corrupted record should surface as Err.
            let ntfs = Ntfs::new(&mut testfs1).unwrap();
            let mut scanner = ntfs
                .deleted_files(&mut testfs1)
                .expect("scanner construction");

            let mut found_error = false;
            while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
                if let Err(NtfsError::MftRecordParseFailed {
                    record_number,
                    source,
                }) = &result
                {
                    assert_eq!(*record_number, corrupt_record);
                    assert!(matches!(**source, NtfsError::InvalidFileSignature { .. }),);
                    found_error = true;
                }
            }
            assert!(
                found_error,
                "scanner should have yielded an error for corrupted record {corrupt_record}",
            );
        }
    }
}
