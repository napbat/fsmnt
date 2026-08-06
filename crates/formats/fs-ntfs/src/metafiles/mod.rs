//! Analyzers for NTFS system metafiles.
//!
//! NTFS reserves the first 16 MFT entries for system metafiles that describe
//! the filesystem structure. This module groups parsers for those metafiles:
//!
//! - [`NtfsAttrDef`] -- `$AttrDef` (MFT entry 4): attribute type definitions
//! - [`NtfsBadClusters`] -- `$BadClus` (MFT entry 8): bad-cluster tracking

mod attr_def;
mod bad_clusters;

pub use attr_def::{NtfsAttrDef, NtfsAttrDefEntries, NtfsAttrDefEntry, NtfsAttrDefFlags};
pub use bad_clusters::NtfsBadClusters;
