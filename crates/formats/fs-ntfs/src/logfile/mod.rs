//! Parser for the NTFS `$LogFile` (MFT record 2).
//!
//! The `$LogFile` contains a transaction journal used by NTFS for crash
//! recovery. It uses a two-layer architecture:
//!
//! - **LFS layer** (Log File Service): manages the circular log format,
//!   restart pages (`RSTR`), record pages (`RCRD`), LSN addressing, and
//!   multi-page record spanning.
//! - **NTFS client layer**: the actual filesystem operations — 33+ operation
//!   codes with typed redo/undo payloads.
//!
//! # Usage
//!
//! ```no_run
//! # use fs_ntfs::Ntfs;
//! # let mut fs = fsmnt_testkit::Cursor::new(vec![]);
//! let ntfs = Ntfs::new(&mut fs).unwrap();
//! let logfile = ntfs.logfile(&mut fs).unwrap();
//!
//! for record in logfile.records() {
//!     println!("LSN {} op {:?}", record.lsn(), record.redo_operation());
//! }
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::attribute::NtfsAttributeType;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;
use fsmnt_parser_core::io::FsReadSeek;

// ---- Page signatures ----
mod operation;
mod parser;
mod records;
mod recovery;
mod views;

pub use parser::operation_is_unit;
#[cfg(test)]
use parser::parse_single_restart_page;
use parser::{
    apply_usa_fixup, le_u16, le_u32, le_u64, parse_operation_data, parse_restart_page,
    walk_resident_data_attrs,
};
use records::parse_file_name_fields;
pub use records::*;
use recovery::{
    build_transaction_states, parse_attribute_names_dump, parse_open_attribute_table_dump,
    parse_open_nonresident_attribute, parse_record_pages, parse_transaction_table_dump,
    select_transaction_table_dump,
};
#[cfg(test)]
use recovery::{parse_single_log_record, parse_utf16le_name};
pub use views::*;

const RESTART_PAGE_SIGNATURE: &[u8; 4] = b"RSTR";
const RECORD_PAGE_SIGNATURE: &[u8; 4] = b"RCRD";

// ---- Restart page header offsets (LFS_RESTART_PAGE_HEADER) ----
const RSTR_OFF_SIGNATURE: usize = 0x00;
const RSTR_OFF_USA_OFFSET: usize = 0x04;
const RSTR_OFF_USA_COUNT: usize = 0x06;
const RSTR_OFF_SYSTEM_PAGE_SIZE: usize = 0x10;
const RSTR_OFF_LOG_PAGE_SIZE: usize = 0x14;
const RSTR_OFF_RESTART_OFFSET: usize = 0x18;
const RSTR_OFF_MINOR_VERSION: usize = 0x1A;
const RSTR_OFF_MAJOR_VERSION: usize = 0x1C;
const RSTR_MIN_HEADER_SIZE: usize = 0x1E;

// ---- LFS_RESTART_AREA offsets (relative to restart_offset) ----
const RA_OFF_CURRENT_LSN: usize = 0x00;
const RA_OFF_FLAGS: usize = 0x0E;
const RA_OFF_SEQ_NUMBER_BITS: usize = 0x10;
const RA_OFF_CLIENT_ARRAY_OFFSET: usize = 0x16;
const RA_OFF_FILE_SIZE: usize = 0x18;
const RA_OFF_LOG_PAGE_DATA_OFFSET: usize = 0x26;
const RA_MIN_SIZE: usize = 0x2C;

// ---- LFS_CLIENT_RECORD offsets (relative to client array start) ----
const CR_OFF_CLIENT_NAME_LENGTH: usize = 0x1C;
const CR_OFF_CLIENT_NAME: usize = 0x20;
const CR_SIZE: usize = 0xA0;

// ---- Record page header offsets (LFS_RECORD_PAGE_HEADER) ----
const RCRD_OFF_USA_OFFSET: usize = 0x04;
const RCRD_OFF_USA_COUNT: usize = 0x06;
const RCRD_OFF_NEXT_RECORD_OFFSET: usize = 0x18;
const RCRD_MIN_HEADER_SIZE: usize = 0x28;

// ---- LFS_RECORD_HEADER offsets ----
const LR_OFF_THIS_LSN: usize = 0x00;
const LR_OFF_CLIENT_PREVIOUS_LSN: usize = 0x08;
const LR_OFF_CLIENT_UNDO_NEXT_LSN: usize = 0x10;
const LR_OFF_CLIENT_DATA_LENGTH: usize = 0x18;
const LR_OFF_RECORD_TYPE: usize = 0x20;
const LR_OFF_TRANSACTION_ID: usize = 0x24;
const LR_OFF_FLAGS: usize = 0x28;
const LR_HEADER_SIZE: usize = 0x30;

// ---- NTFS_LOG_RECORD offsets (client data, after LFS header) ----
const NR_OFF_REDO_OP: usize = 0x00;
const NR_OFF_UNDO_OP: usize = 0x02;
const NR_OFF_REDO_OFFSET: usize = 0x04;
const NR_OFF_REDO_LENGTH: usize = 0x06;
const NR_OFF_UNDO_OFFSET: usize = 0x08;
const NR_OFF_UNDO_LENGTH: usize = 0x0A;
const NR_OFF_TARGET_ATTRIBUTE: usize = 0x0C;
const NR_OFF_LCNS_TO_FOLLOW: usize = 0x0E;
const NR_OFF_RECORD_OFFSET: usize = 0x10;
const NR_OFF_ATTRIBUTE_OFFSET: usize = 0x12;
const NR_OFF_CLUSTER_BLOCK_OFFSET: usize = 0x14;
const NR_OFF_TARGET_VCN: usize = 0x18;
const NR_FIXED_HEADER_SIZE: usize = 0x20;

// ---- LFS restart area flags ----
const RESTART_CLEAN_DISMOUNT: u16 = 0x0002;

// ---- Log record flags ----
const LOG_RECORD_MULTI_PAGE: u16 = 0x0001;

// ---- LFS record types ----
const LFS_CLIENT_RECORD: u32 = 0x01;
const LFS_CLIENT_RESTART: u32 = 0x02;

// ---- Update Sequence Array stride ----
const USA_STRIDE: usize = 512;

// ---- NTFS client restart area offsets ----
const NCR_OFF_MAJOR_VERSION: usize = 0x00;
const NCR_OFF_MINOR_VERSION: usize = 0x04;
const NCR_OFF_START_OF_CHECKPOINT_LSN: usize = 0x08;
const NCR_OFF_OPEN_ATTR_TABLE_LSN: usize = 0x10;
const NCR_OFF_ATTR_NAMES_LSN: usize = 0x18;
const NCR_OFF_DIRTY_PAGE_TABLE_LSN: usize = 0x20;
const NCR_OFF_TRANSACTION_TABLE_LSN: usize = 0x28;
const NCR_MIN_SIZE: usize = 0x40;

// ---- Open attribute entry offsets (version 0.0 — used with LFS v1.1) ----
const OAE0_OFF_FILE_REFERENCE: usize = 0x08;
const OAE0_OFF_LSN_OF_OPEN: usize = 0x10;
const OAE0_OFF_ATTR_TYPE: usize = 0x1C;
const OAE0_OFF_BYTES_PER_INDEX: usize = 0x28;
const OAE0_SIZE: usize = 0x2C;

// ---- Open attribute entry offsets (version 1.0 — used with LFS v2.0) ----
const OAE1_OFF_BYTES_PER_INDEX: usize = 0x04;
const OAE1_OFF_ATTR_TYPE: usize = 0x08;
const OAE1_OFF_FILE_REFERENCE: usize = 0x10;
const OAE1_OFF_LSN_OF_OPEN: usize = 0x18;
const OAE1_SIZE: usize = 0x28;

// ---- Attribute name entry offsets ----
const ANE_OFF_INDEX: usize = 0x00;
const ANE_OFF_NAME_LENGTH: usize = 0x02;
const ANE_OFF_NAME: usize = 0x04;

// ---- FILE record header offsets (for LogFileRecordView) ----
const FILE_SIGNATURE: &[u8; 4] = b"FILE";
const FR_OFF_USA_OFFSET: usize = 0x04;
const FR_OFF_USA_COUNT: usize = 0x06;
const FR_OFF_SEQUENCE_NUMBER: usize = 0x10;
const FR_OFF_HARD_LINK_COUNT: usize = 0x12;
const FR_OFF_FIRST_ATTRIBUTE_OFFSET: usize = 0x14;
const FR_OFF_FLAGS: usize = 0x16;
const FR_OFF_USED_SIZE: usize = 0x18;
const FR_OFF_ALLOCATED_SIZE: usize = 0x1C;
const FR_OFF_BASE_FILE_REFERENCE: usize = 0x20;
const FR_MIN_HEADER_SIZE: usize = 0x2A; // 42 bytes

// ---- Attribute record header offsets (for walk_resident_data_attrs) ----
const ATTR_OFF_TYPE: usize = 0x00;
const ATTR_OFF_LENGTH: usize = 0x04;
const ATTR_OFF_NON_RESIDENT: usize = 0x08;
const ATTR_OFF_NAME_LENGTH: usize = 0x09;
const ATTR_OFF_NAME_OFFSET: usize = 0x0A;
const ATTR_OFF_INSTANCE: usize = 0x0E;
const ATTR_MIN_HEADER_SIZE: usize = 0x10;

// ---- Resident attribute extension offsets ----
const RES_OFF_VALUE_LENGTH: usize = 0x10;
const RES_OFF_VALUE_OFFSET: usize = 0x14;
const RES_MIN_HEADER_SIZE: usize = 0x18;

// ---- Attribute end marker ----
const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

// ---- $DATA attribute type code ----
const ATTR_TYPE_DATA: u32 = 0x80;
const MAX_LOGFILE_SIZE: u64 = 256 * 1024 * 1024;

// ---- Index entry header offsets (for LogIndexEntryView) ----
const IE_OFF_FILE_REFERENCE: usize = 0x00;
const IE_OFF_INDEX_ENTRY_LENGTH: usize = 0x08;
const IE_OFF_KEY_LENGTH: usize = 0x0A;
const IE_OFF_FLAGS: usize = 0x0C;
const IE_HEADER_SIZE: usize = 0x10; // 16 bytes

// ---- Index entry flags ----
const IE_FLAG_HAS_SUBNODE: u16 = 0x0001;
const IE_FLAG_LAST_ENTRY: u16 = 0x0002;

// ---- FILE_NAME field offsets (for LogFileNameFields) ----
const FN_OFF_PARENT_REF: usize = 0x00;
const FN_OFF_CREATION_TIME: usize = 0x08;
const FN_OFF_MODIFICATION: usize = 0x10;
const FN_OFF_MFT_MODIFIED: usize = 0x18;
const FN_OFF_ACCESS_TIME: usize = 0x20;
const FN_OFF_ALLOCATED_SIZE: usize = 0x28;
const FN_OFF_DATA_SIZE: usize = 0x30;
const FN_OFF_FILE_ATTRIBUTES: usize = 0x38;
const FN_OFF_NAME_LENGTH: usize = 0x40;
const FN_OFF_NAMESPACE: usize = 0x41;
const FN_FIXED_SIZE: usize = 0x42; // 66 bytes

// ---- Transaction table entry offsets ----
const TTE_OFF_ALLOCATED: usize = 0x00;
const TTE_OFF_STATE: usize = 0x04;
const TTE_OFF_FIRST_LSN: usize = 0x08;
const TTE_OFF_PREVIOUS_LSN: usize = 0x10;
const TTE_OFF_UNDO_NEXT_LSN: usize = 0x18;
const TTE_OFF_UNDO_RECORDS: usize = 0x20;
const TTE_OFF_UNDO_BYTES: usize = 0x24;
const TTE_SIZE: usize = 0x28;
const TTE_ALLOCATED_MARKER: u32 = 0xFFFF_FFFF;

/// The parsed `$LogFile` -- top-level container for all log data.
///
/// Created via [`NtfsLogFile::load`] or [`Ntfs::logfile`].
#[derive(Clone, Debug)]
pub struct NtfsLogFile {
    restart_info: LfsRestartInfo,
    client_restart: Option<NtfsClientRestartArea>,
    open_attribute_table: Vec<OpenAttributeEntry>,
    attribute_names: Vec<AttributeNameEntry>,
    transaction_table_dump: Vec<TransactionTableDumpEntry>,
    transaction_states: alloc::collections::BTreeMap<u32, TransactionEntry>,
    records: Vec<NtfsLogRecord>,
    skipped_pages: u32,
}

impl NtfsLogFile {
    /// Load and parse the `$LogFile` from an NTFS filesystem.
    ///
    /// Opens MFT record 2, reads the `$DATA` attribute, and parses all
    /// restart pages and log record pages.
    ///
    /// # Errors
    ///
    /// Returns an error if the NTFS log data is malformed or cannot be read from the underlying stream.
    pub fn load<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        let logfile_file = ntfs.file(fs, KnownNtfsFileRecordNumber::LogFile.as_u64())?;

        let data_attr = logfile_file
            .attributes_raw()
            .find_map(|attr| {
                let attr = attr.ok()?;
                if attr.ty().ok()? == NtfsAttributeType::Data {
                    Some(attr)
                } else {
                    None
                }
            })
            .ok_or(NtfsError::InvalidLogFileRecord {
                position: NtfsPosition::none(),
                reason: "$LogFile has no $DATA attribute",
            })?;

        let mut value = data_attr.value(fs)?;
        let raw_len = value.len();
        if raw_len > MAX_LOGFILE_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position: NtfsPosition::none(),
                reason: "$LogFile data exceeds 256 MB limit",
            });
        }
        let len = usize::try_from(raw_len).map_err(|_| NtfsError::InvalidLogFileRecord {
            position: NtfsPosition::none(),
            reason: "$LogFile data does not fit in the address space",
        })?;
        let mut data = vec![0u8; len];
        value.read_exact(fs, &mut data)?;

        let position = NtfsPosition::none();

        let restart_info = parse_restart_page(&data, position)?;

        let (records, skipped_pages) = parse_record_pages(&data, &restart_info, position);

        let mut client_restart = None;
        let mut open_attribute_table = Vec::new();
        let mut attribute_names = Vec::new();
        let mut txn_dump_candidates: Vec<(u64, Vec<TransactionTableDumpEntry>)> = Vec::new();

        for record in &records {
            if record.record_type() == LogRecordType::ClientRestart
                && let NtfsLogOperationData::Raw { data: ref cr_data } = record.redo_data
                && cr_data.len() >= NCR_MIN_SIZE
            {
                client_restart = Some(NtfsClientRestartArea {
                    major_version: le_u32(cr_data, NCR_OFF_MAJOR_VERSION),
                    minor_version: le_u32(cr_data, NCR_OFF_MINOR_VERSION),
                    start_of_checkpoint_lsn: le_u64(cr_data, NCR_OFF_START_OF_CHECKPOINT_LSN),
                    open_attribute_table_lsn: le_u64(cr_data, NCR_OFF_OPEN_ATTR_TABLE_LSN),
                    attribute_names_lsn: le_u64(cr_data, NCR_OFF_ATTR_NAMES_LSN),
                    dirty_page_table_lsn: le_u64(cr_data, NCR_OFF_DIRTY_PAGE_TABLE_LSN),
                    transaction_table_lsn: le_u64(cr_data, NCR_OFF_TRANSACTION_TABLE_LSN),
                });
            }

            if let NtfsLogOperationData::OpenAttributeTableDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                open_attribute_table.clone_from(dump_entries);
            }

            if let NtfsLogOperationData::AttributeNamesDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                attribute_names.clone_from(dump_entries);
            }

            if let NtfsLogOperationData::TransactionTableDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                txn_dump_candidates.push((record.lsn(), dump_entries.clone()));
            }
        }

        // Select the best TransactionTableDump: exact match on
        // transaction_table_lsn, then closest at/after, then
        // closest before. Falls back to last candidate if no
        // client restart is available.
        let transaction_table_dump =
            select_transaction_table_dump(&txn_dump_candidates, client_restart.as_ref());

        let baseline_lsn = if transaction_table_dump.is_empty() {
            0
        } else {
            client_restart
                .as_ref()
                .map_or(0, records::NtfsClientRestartArea::transaction_table_lsn)
        };

        let transaction_states =
            build_transaction_states(&transaction_table_dump, &records, baseline_lsn);

        Ok(Self {
            restart_info,
            client_restart,
            open_attribute_table,
            attribute_names,
            transaction_table_dump,
            transaction_states,
            records,
            skipped_pages,
        })
    }

    /// The LFS restart information.
    #[must_use]
    pub fn restart_info(&self) -> &LfsRestartInfo {
        &self.restart_info
    }

    /// The NTFS client restart area (checkpoint data), if found.
    #[must_use]
    pub fn client_restart(&self) -> Option<&NtfsClientRestartArea> {
        self.client_restart.as_ref()
    }

    /// All parsed log records, ordered by LSN.
    #[must_use]
    pub fn records(&self) -> &[NtfsLogRecord] {
        &self.records
    }

    /// Look up a record by its LSN.
    #[must_use]
    pub fn record_by_lsn(&self, lsn: u64) -> Option<&NtfsLogRecord> {
        self.records
            .binary_search_by_key(&lsn, |r| r.lsn)
            .ok()
            .map(|idx| &self.records[idx])
    }

    /// Group records by transaction ID.
    #[must_use]
    pub fn transactions(&self) -> alloc::collections::BTreeMap<u32, Vec<&NtfsLogRecord>> {
        let mut map: alloc::collections::BTreeMap<u32, Vec<&NtfsLogRecord>> =
            alloc::collections::BTreeMap::new();
        for record in &self.records {
            if record.record_type() == LogRecordType::ClientRecord {
                map.entry(record.transaction_id()).or_default().push(record);
            }
        }
        map
    }

    /// The open attribute table.
    #[must_use]
    pub fn open_attribute_table(&self) -> &[OpenAttributeEntry] {
        &self.open_attribute_table
    }

    /// Attribute name entries from the most recent checkpoint.
    #[must_use]
    pub fn attribute_names(&self) -> &[AttributeNameEntry] {
        &self.attribute_names
    }

    /// Transaction table entries from the checkpoint dump.
    #[must_use]
    pub fn transaction_table_dump(&self) -> &[TransactionTableDumpEntry] {
        &self.transaction_table_dump
    }

    /// Transaction lifecycle states, keyed by transaction
    /// table slot index.
    #[must_use]
    pub fn transaction_states(&self) -> &alloc::collections::BTreeMap<u32, TransactionEntry> {
        &self.transaction_states
    }

    /// Look up a single transaction by its table slot index.
    #[must_use]
    pub fn transaction_state(&self, id: u32) -> Option<&TransactionEntry> {
        self.transaction_states.get(&id)
    }

    /// Transactions that never reached end-of-life
    /// (`ForgetTransaction` not observed).
    pub fn incomplete_transactions(&self) -> impl Iterator<Item = &TransactionEntry> + '_ {
        self.transaction_states
            .values()
            .filter(|e| e.is_incomplete())
    }

    /// Number of corrupt record pages skipped during parsing.
    #[must_use]
    pub fn skipped_pages(&self) -> u32 {
        self.skipped_pages
    }
}

#[cfg(test)]
#[path = "../logfile_tests/mod.rs"]
mod tests;
