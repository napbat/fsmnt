//! Forensic analysis utilities for NTFS data.
//!
//! Some functions are pure computation over already-parsed structures
//! (e.g., timestamp analysis), while others require a filesystem reader
//! for additional I/O (e.g., MFT mirror validation).

pub mod mft_mirror;
pub mod timestamps;

pub use mft_mirror::{NtfsMftMirrRecordStatus, NtfsMftMirrValidation, validate_mft_mirror};
pub use timestamps::{
    NtfsTimestampAnomaly, detect_timestamp_anomalies, detect_timestamp_anomalies_with_threshold,
};
