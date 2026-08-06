//! Assembled directory entry sets for exFAT.
//!
//! An exFAT file or directory is represented on disk as an "entry set":
//! one primary [`FileDirectoryEntry`] (0x85) followed by one or more
//! secondary entries -- a [`StreamExtensionEntry`] (0xC0) and one or
//! more [`FileNameEntry`] (0xC1) entries that together carry the
//! complete file name.
//!
//! This module provides:
//! - [`ExFatEntrySet`] -- the assembled, validated entry set with
//!   accessors for name, attributes, timestamps, and stream info.
//! - [`ExFatDirItem`] -- the enum yielded by the directory iterator.
//! - [`compute_set_checksum`] -- the rotate-right checksum algorithm.

use alloc::string::String;
use alloc::vec::Vec;

use crate::dir_entry::{
    ExFatFileAttributes, FileDirectoryEntry, FileNameEntry, StreamExtensionEntry, VolumeLabelEntry,
};
use crate::time::ExFatTimestamp;

// ============================================================
// SetChecksum computation
// ============================================================

/// Computes the entry set checksum over raw entry set bytes.
///
/// The algorithm rotates the 16-bit accumulator right by one bit
/// (with carry) and adds each byte, skipping bytes 2 and 3 which
/// hold the `SetChecksum` field itself in the primary entry.
pub(crate) fn compute_set_checksum(entries: &[u8]) -> u16 {
    let mut checksum: u16 = 0;
    for (i, &byte) in entries.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        let bit0 = if checksum & 1 != 0 { 0x8000u16 } else { 0u16 };
        checksum = bit0
            .wrapping_add(checksum >> 1)
            .wrapping_add(u16::from(byte));
    }
    checksum
}

// ============================================================
// ExFatDirItem
// ============================================================

/// An item yielded by the directory entry iterator.
///
/// Each item is either a complete file/directory entry set or a
/// volume label string.
#[derive(Clone, Debug)]
pub enum ExFatDirItem {
    /// A complete file or directory entry set.
    FileEntry(ExFatEntrySet),
    /// The volume label decoded from a 0x83 entry.
    VolumeLabel(String),
    /// A benign entry (e.g., Volume GUID, `TexFAT` Padding,
    /// Vendor Extension, Vendor Allocation).
    ///
    /// Only yielded when the iterator's `include_benign` option
    /// is enabled.
    BenignEntry {
        /// The raw entry type byte.
        entry_type: u8,
        /// The raw 32-byte on-disk entry data.
        data: [u8; 32],
        /// Byte offset of this entry on the volume.
        byte_offset: u64,
    },
    /// A deleted/not-in-use entry (bit 7 clear, type code > 0).
    ///
    /// Only yielded when the iterator's `include_deleted` option
    /// is enabled. Useful for forensic deleted-file recovery.
    DeletedEntry {
        /// The raw entry type byte.
        entry_type: u8,
        /// The raw 32-byte on-disk entry data.
        data: [u8; 32],
        /// Byte offset of this entry on the volume.
        byte_offset: u64,
    },
}

// ============================================================
// ExFatEntrySet
// ============================================================

/// An assembled file entry set containing the primary file entry,
/// stream extension, assembled file name, and checksum validation
/// status.
#[derive(Clone, Debug)]
pub struct ExFatEntrySet {
    file_entry: FileDirectoryEntry,
    stream_entry: StreamExtensionEntry,
    name_chars: Vec<u16>,
    name_utf16le: Vec<u8>,
    checksum_valid: bool,
}

impl ExFatEntrySet {
    /// Assembles an entry set from its constituent parts.
    ///
    /// Called by the directory iterator after collecting all entries
    /// in the set. Validates the checksum by computing it over
    /// `raw_bytes` and comparing to the stored value.
    pub(crate) fn assemble(
        file_entry: FileDirectoryEntry,
        stream_entry: StreamExtensionEntry,
        name_entries: &[FileNameEntry],
        raw_bytes: &[u8],
    ) -> Self {
        let name_chars = assemble_file_name(name_entries, stream_entry.name_length);
        let mut name_utf16le = Vec::with_capacity(name_chars.len() * 2);
        for &ch in &name_chars {
            name_utf16le.extend_from_slice(&ch.to_le_bytes());
        }
        let computed = compute_set_checksum(raw_bytes);
        let stored = file_entry.set_checksum.get();
        Self {
            file_entry,
            stream_entry,
            name_chars,
            name_utf16le,
            checksum_valid: computed == stored,
        }
    }

    // --------------------------------------------------------
    // Name accessors
    // --------------------------------------------------------

    /// Returns the raw UTF-16 code units of the file name.
    #[must_use]
    pub fn name(&self) -> &[u16] {
        &self.name_chars
    }

    /// Returns the file name as raw UTF-16LE bytes.
    #[must_use]
    pub fn name_utf16le(&self) -> &[u8] {
        &self.name_utf16le
    }

    /// Returns the file name as a Rust `String`, replacing invalid
    /// UTF-16 sequences with the Unicode replacement character.
    #[must_use]
    pub fn name_string(&self) -> String {
        String::from_utf16_lossy(&self.name_chars)
    }

    // --------------------------------------------------------
    // Attribute accessors
    // --------------------------------------------------------

    /// Returns the file attribute flags.
    #[must_use]
    pub fn file_attributes(&self) -> ExFatFileAttributes {
        ExFatFileAttributes::from_bits_truncate(self.file_entry.file_attributes.get())
    }

    /// Returns `true` if this entry represents a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_attributes()
            .contains(ExFatFileAttributes::DIRECTORY)
    }

    // --------------------------------------------------------
    // Stream info accessors
    // --------------------------------------------------------

    /// Returns the stored `NameHash` from the stream extension entry.
    ///
    /// This is the hash of the up-cased file name as stored on disk.
    /// Use [`crate::upcase::compute_name_hash`] to compute a hash
    /// for comparison during directory search.
    #[must_use]
    pub fn name_hash(&self) -> u16 {
        self.stream_entry.name_hash.get()
    }

    /// Returns the first cluster of the data stream.
    #[must_use]
    pub fn first_cluster(&self) -> u32 {
        self.stream_entry.first_cluster.get()
    }

    /// Returns the allocated data length in bytes.
    #[must_use]
    pub fn data_length(&self) -> u64 {
        self.stream_entry.data_length.get()
    }

    /// Returns the valid data length in bytes.
    #[must_use]
    pub fn valid_data_length(&self) -> u64 {
        self.stream_entry.valid_data_length.get()
    }

    /// Returns `true` if the `NoFatChain` flag is set (contiguous
    /// allocation, no FAT chain traversal needed).
    #[must_use]
    pub fn no_fat_chain(&self) -> bool {
        self.stream_entry.general_flags & 0x02 != 0
    }

    // --------------------------------------------------------
    // Checksum accessor
    // --------------------------------------------------------

    /// Returns `true` if the computed checksum matches the stored
    /// `SetChecksum` value.
    #[must_use]
    pub fn checksum_valid(&self) -> bool {
        self.checksum_valid
    }

    /// Returns the number of secondary entries in this set.
    #[must_use]
    pub fn secondary_count(&self) -> u8 {
        self.file_entry.secondary_count
    }

    // --------------------------------------------------------
    // Timestamp accessors
    // --------------------------------------------------------

    /// Returns the creation timestamp.
    #[must_use]
    pub fn create_timestamp(&self) -> ExFatTimestamp {
        ExFatTimestamp::new(
            self.file_entry.create_date.get(),
            self.file_entry.create_time.get(),
            self.file_entry.create_time_cs,
            self.file_entry.create_tz,
        )
    }

    /// Returns the last modification timestamp.
    #[must_use]
    pub fn modify_timestamp(&self) -> ExFatTimestamp {
        ExFatTimestamp::new(
            self.file_entry.modify_date.get(),
            self.file_entry.modify_time.get(),
            self.file_entry.modify_time_cs,
            self.file_entry.modify_tz,
        )
    }

    /// Returns the last access timestamp.
    ///
    /// Access timestamps have no 10ms increment field, so
    /// `ten_ms` is always zero.
    #[must_use]
    pub fn access_timestamp(&self) -> ExFatTimestamp {
        ExFatTimestamp::new(
            self.file_entry.access_date.get(),
            self.file_entry.access_time.get(),
            0,
            self.file_entry.access_tz,
        )
    }
}

// ============================================================
// File name assembly
// ============================================================

/// Assembles a file name from one or more [`FileNameEntry`] entries.
///
/// Each entry carries up to 15 UTF-16LE code units (30 bytes).
/// The `name_length` from the stream extension entry limits the
/// total number of characters extracted.
fn assemble_file_name(entries: &[FileNameEntry], name_length: u8) -> Vec<u16> {
    let limit = usize::from(name_length);
    let mut chars = Vec::with_capacity(limit);
    for entry in entries {
        for i in 0..15 {
            if chars.len() >= limit {
                break;
            }
            let lo = entry.file_name[i * 2];
            let hi = entry.file_name[i * 2 + 1];
            chars.push(u16::from_le_bytes([lo, hi]));
        }
    }
    chars.truncate(limit);
    chars
}

// ============================================================
// Volume label decoding
// ============================================================

/// Decodes a volume label from a [`VolumeLabelEntry`].
///
/// The label is stored as UTF-16LE with up to 11 characters
/// (22 bytes). The `character_count` field limits extraction.
pub(crate) fn decode_volume_label(entry: &VolumeLabelEntry) -> String {
    let count = usize::from(entry.character_count.min(11));
    let mut chars = Vec::with_capacity(count);
    for i in 0..count {
        let lo = entry.volume_label[i * 2];
        let hi = entry.volume_label[i * 2 + 1];
        chars.push(u16::from_le_bytes([lo, hi]));
    }
    String::from_utf16_lossy(&chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_computation_known_value() {
        // Build a 3-entry (96 byte) entry set: primary + stream +
        // name. Fill with known pattern, compute checksum, write
        // it back, then verify compute_set_checksum matches.
        let mut raw = vec![0xAAu8; 96];
        // Write the checksum field (bytes 2-3) to zero first so
        // we can compute the "real" checksum.
        raw[2] = 0;
        raw[3] = 0;
        let checksum = compute_set_checksum(&raw);
        raw[2..4].copy_from_slice(&checksum.to_le_bytes());
        // Now verify that compute_set_checksum still gives the
        // same result (it skips bytes 2-3).
        assert_eq!(compute_set_checksum(&raw), checksum);
    }

    #[test]
    fn checksum_skips_bytes_2_3() {
        let mut raw = vec![0x55u8; 64];
        let c1 = compute_set_checksum(&raw);
        // Change bytes 2 and 3 -- checksum must not change.
        raw[2] = 0xFF;
        raw[3] = 0x00;
        let c2 = compute_set_checksum(&raw);
        assert_eq!(c1, c2);
    }

    #[test]
    fn file_name_assembly_short() {
        // "test.txt" = 8 UTF-16LE chars
        let expected: Vec<u16> = "test.txt".encode_utf16().collect();
        assert_eq!(expected.len(), 8);

        let mut name_bytes = [0u8; 30];
        for (i, &ch) in expected.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            name_bytes[i * 2] = lo;
            name_bytes[i * 2 + 1] = hi;
        }

        let entry = FileNameEntry {
            entry_type: 0xC1,
            general_flags: 0,
            file_name: name_bytes,
        };

        let result = assemble_file_name(&[entry], 8);
        assert_eq!(result, expected);
    }

    #[test]
    fn file_name_assembly_multi_entry() {
        // 20-char name that spans two FileNameEntry entries
        let name = "abcdefghijklmnopqrst";
        let expected: Vec<u16> = name.encode_utf16().collect();
        assert_eq!(expected.len(), 20);

        let mut entry1_bytes = [0u8; 30];
        for (i, &ch) in expected[..15].iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            entry1_bytes[i * 2] = lo;
            entry1_bytes[i * 2 + 1] = hi;
        }

        let mut entry2_bytes = [0u8; 30];
        for (i, &ch) in expected[15..].iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            entry2_bytes[i * 2] = lo;
            entry2_bytes[i * 2 + 1] = hi;
        }

        let entries = [
            FileNameEntry {
                entry_type: 0xC1,
                general_flags: 0,
                file_name: entry1_bytes,
            },
            FileNameEntry {
                entry_type: 0xC1,
                general_flags: 0,
                file_name: entry2_bytes,
            },
        ];

        let result = assemble_file_name(&entries, 20);
        assert_eq!(result, expected);
        assert_eq!(String::from_utf16_lossy(&result), "abcdefghijklmnopqrst");
    }

    #[test]
    fn entry_set_name_hash_accessor() {
        use crate::dir_entry::*;
        use zerocopy::FromBytes;

        let mut raw = vec![0u8; 3 * DIR_ENTRY_SIZE];

        // Primary entry (0x85)
        raw[0] = ENTRY_TYPE_FILE;
        raw[1] = 2; // secondary_count

        // Stream extension (0xC0) at offset 32
        raw[32] = ENTRY_TYPE_STREAM;
        raw[33] = 0x01; // AllocationPossible
        raw[35] = 8; // name_length = 8 chars
        // name_hash at offset 36-37 (bytes 4-5 of stream entry)
        raw[36] = 0xAB;
        raw[37] = 0xCD;

        // File name (0xC1) at offset 64
        raw[64] = ENTRY_TYPE_NAME;
        let name_utf16: Vec<u16> = "test.txt".encode_utf16().collect();
        for (i, &ch) in name_utf16.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            raw[66 + i * 2] = lo;
            raw[66 + i * 2 + 1] = hi;
        }

        // Write correct checksum
        let checksum = compute_set_checksum(&raw);
        raw[2..4].copy_from_slice(&checksum.to_le_bytes());

        let file = FileDirectoryEntry::read_from_bytes(&raw[0..32]).unwrap();
        let stream = StreamExtensionEntry::read_from_bytes(&raw[32..64]).unwrap();
        let name_entry = FileNameEntry::read_from_bytes(&raw[64..96]).unwrap();

        let es = ExFatEntrySet::assemble(
            file.clone(),
            stream.clone(),
            core::slice::from_ref(&name_entry),
            &raw,
        );
        assert_eq!(es.name_hash(), 0xCDAB);
    }

    /// Pins `compute_set_checksum` to its concrete spec-mandated
    /// algorithm: rotate-right by one bit (with carry into bit 15)
    /// plus add-with-wrap. Asserting a manually-computed value for a
    /// known input simultaneously kills every mutant that replaces
    /// the body with a constant or swaps the carry test/shift
    /// direction.
    #[test]
    fn compute_set_checksum_known_value() {
        // Trace for [0xFF; 4] (bytes 2,3 skipped):
        //   i=0: bit0=(0&1!=0)?…=0. checksum = 0 + (0>>1) + 0xFF = 0x00FF.
        //   i=1: bit0=(0xFF&1!=0)?0x8000=0x8000.
        //         checksum = 0x8000 + (0xFF>>1) + 0xFF
        //                  = 0x8000 + 0x007F + 0x00FF = 0x817E.
        //   i=2,3: skipped.
        assert_eq!(compute_set_checksum(&[0xFF; 4]), 0x817E);
    }

    /// Builds a minimal 3-entry raw byte buffer (primary + stream +
    /// one name entry) with the given stream `general_flags` and
    /// `valid_data_length`, returning the assembled entry set. Used
    /// by the dedicated accessor tests below.
    fn build_entry_set(name: &str, general_flags: u8, valid_data_length: u64) -> ExFatEntrySet {
        use crate::dir_entry::*;
        use zerocopy::FromBytes;

        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut raw = vec![0u8; 3 * DIR_ENTRY_SIZE];

        // Primary (0x85)
        raw[0] = ENTRY_TYPE_FILE;
        raw[1] = 2; // secondary_count

        // Stream (0xC0)
        raw[32] = ENTRY_TYPE_STREAM;
        raw[33] = general_flags;
        raw[35] = u8::try_from(utf16.len()).expect("test name fits the exFAT length field");
        raw[40..48].copy_from_slice(&valid_data_length.to_le_bytes());

        // Name (0xC1)
        raw[64] = ENTRY_TYPE_NAME;
        for (i, &ch) in utf16.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            raw[66 + i * 2] = lo;
            raw[66 + i * 2 + 1] = hi;
        }

        // Write correct SetChecksum.
        let cs = compute_set_checksum(&raw);
        raw[2..4].copy_from_slice(&cs.to_le_bytes());

        let file = FileDirectoryEntry::read_from_bytes(&raw[0..32]).unwrap();
        let stream = StreamExtensionEntry::read_from_bytes(&raw[32..64]).unwrap();
        let name_entry = FileNameEntry::read_from_bytes(&raw[64..96]).unwrap();

        ExFatEntrySet::assemble(file, stream, core::slice::from_ref(&name_entry), &raw)
    }

    /// `name_utf16le` returns the file name as raw UTF-16LE bytes.
    /// Asserting the exact bytes for an ASCII name kills mutations
    /// that substitute `Vec::leak(Vec::new())` or `vec![0]` / `vec![1]`.
    #[test]
    fn name_utf16le_returns_correct_bytes() {
        let es = build_entry_set("ABC", 0, 0);
        // 'A','B','C' in UTF-16LE = [0x41,0x00, 0x42,0x00, 0x43,0x00].
        assert_eq!(es.name_utf16le(), &[0x41, 0x00, 0x42, 0x00, 0x43, 0x00]);
    }

    /// Pins `valid_data_length` to the field stored in the stream
    /// extension entry; kills `→ 0` / `→ 1` accessor mutations.
    #[test]
    fn valid_data_length_accessor_returns_stored_value() {
        let es = build_entry_set("X", 0, 42);
        assert_eq!(es.valid_data_length(), 42);
    }

    /// `no_fat_chain` reflects bit 1 of `general_flags`. Testing all
    /// four 2-bit combinations pins the operator (`&` vs `|`, `^`)
    /// and the truth value (`→ true`).
    #[test]
    fn no_fat_chain_reflects_general_flags_bit_1() {
        // bit 1 clear → false
        assert!(!build_entry_set("a", 0x00, 0).no_fat_chain());
        // bit 0 set, bit 1 clear → still false (kills `&` → `|`).
        assert!(!build_entry_set("a", 0x01, 0).no_fat_chain());
        // bit 1 set, bit 0 clear → true.
        assert!(build_entry_set("a", 0x02, 0).no_fat_chain());
        // both bits set → still true (kills `&` → `^`, which would
        // give `0x03 ^ 0x02 = 0x01 != 0 = true` here but inverts the
        // 0x02-only case above).
        assert!(build_entry_set("a", 0x03, 0).no_fat_chain());
    }

    #[test]
    fn volume_label_decode() {
        let label = "TEST";
        let utf16: Vec<u16> = label.encode_utf16().collect();
        let mut label_bytes = [0u8; 22];
        for (i, &ch) in utf16.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            label_bytes[i * 2] = lo;
            label_bytes[i * 2 + 1] = hi;
        }

        let entry = VolumeLabelEntry {
            entry_type: 0x83,
            character_count: 4,
            volume_label: label_bytes,
            reserved: [0; 8],
        };

        assert_eq!(decode_volume_label(&entry), "TEST");
    }
}
