use crate::error::{ExFatError, Result};
use alloc::vec;
use alloc::vec::Vec;

/// Computes the up-case table checksum over raw (compressed) bytes.
///
/// Same rotate-right-by-1 u32 + add algorithm as the VBR boot
/// checksum, but without any byte-skipping.
#[must_use]
pub fn compute_upcase_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for &byte in data {
        let bit0 = if checksum & 1 != 0 { 0x8000_0000u32 } else { 0 };
        checksum = bit0
            .wrapping_add(checksum >> 1)
            .wrapping_add(u32::from(byte));
    }
    checksum
}

/// Decompresses the on-disk upcase table into a 65,536-entry table.
///
/// Compression format:
/// - `0xFFFF` marker followed by a count -> skip that many
///   identity-mapped entries
/// - Value equal to current index -> identity mapping (stored as 0)
/// - Other value -> non-identity mapping (store the value)
fn decompress_upcase_table(compressed: &[u8]) -> Result<Vec<u16>> {
    let mut table = vec![0u16; 65_536];
    let mut index: usize = 0;
    let mut i = 0;
    let mut skip = false;

    while i + 1 < compressed.len() && index <= 0xFFFF {
        let value = u16::from_le_bytes([compressed[i], compressed[i + 1]]);
        i += 2;

        if skip {
            index += usize::from(value);
            skip = false;
        } else if usize::from(value) == index {
            // Identity mapping — table[index] is already 0.
            // Must check before 0xFFFF marker so that U+FFFF at
            // index 0xFFFF is treated as identity, not a marker.
            index += 1;
        } else if value == 0xFFFF {
            skip = true;
        } else {
            table[index] = value;
            index += 1;
        }
    }

    if index < 0x10000 {
        return Err(ExFatError::InvalidUpcaseTable {
            reason: "table incomplete after decompression",
        });
    }

    Ok(table)
}

/// Decompressed up-case table for an exFAT volume.
///
/// Maps each UTF-16 code unit (U+0000..U+FFFF) to its uppercase
/// equivalent. Identity-mapped entries are stored as 0; the lookup
/// function returns the original character in that case.
#[derive(Debug, Clone)]
pub struct ExFatUpcaseTable {
    table: Vec<u16>,
}

impl ExFatUpcaseTable {
    /// Loads and validates an up-case table from raw on-disk data.
    ///
    /// Computes the checksum over the raw (compressed) bytes, compares
    /// it to `expected_checksum`, then decompresses the table.
    ///
    /// # Errors
    ///
    /// Returns an error if the checksum differs or the compressed data
    /// does not describe the complete 65,536-code-unit table.
    pub fn load(raw_data: &[u8], expected_checksum: u32) -> Result<Self> {
        let actual = compute_upcase_checksum(raw_data);
        if actual != expected_checksum {
            return Err(ExFatError::UpcaseChecksumMismatch {
                expected: expected_checksum,
                actual,
            });
        }
        let table = decompress_upcase_table(raw_data)?;
        Ok(Self { table })
    }

    /// Creates a table from an already-decompressed 65,536-entry vector.
    #[cfg(test)]
    pub(crate) fn from_decompressed(table: Vec<u16>) -> Self {
        Self { table }
    }

    /// Returns the uppercase equivalent of a UTF-16 code unit.
    ///
    /// If the table stores 0 for the given character, it is
    /// identity-mapped (character maps to itself).
    #[must_use]
    pub fn upcase(&self, ch: u16) -> u16 {
        let mapped = self.table[usize::from(ch)];
        if mapped != 0 { mapped } else { ch }
    }

    /// Computes the `NameHash` for a file name (applies upcase first).
    #[must_use]
    pub fn name_hash_for_name(&self, name: &[u16]) -> u16 {
        let upcased: Vec<u16> = name.iter().map(|&ch| self.upcase(ch)).collect();
        compute_name_hash(&upcased)
    }

    /// Compares two UTF-16 names case-insensitively using the
    /// upcase table.
    #[must_use]
    pub fn names_equal(&self, a: &[u16], b: &[u16]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .all(|(&ac, &bc)| self.upcase(ac) == self.upcase(bc))
    }

    /// Compares a UTF-16 name against a `&str` case-insensitively.
    ///
    /// Avoids heap allocation by using `str::encode_utf16` iterator.
    #[must_use]
    pub fn name_equals_str(&self, name: &[u16], s: &str) -> bool {
        let mut name_iter = name.iter().copied();
        let mut str_iter = s.encode_utf16();
        loop {
            match (name_iter.next(), str_iter.next()) {
                (Some(a), Some(b)) => {
                    if self.upcase(a) != self.upcase(b) {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

/// Computes the `NameHash` checksum over up-cased UTF-16LE bytes.
///
/// The input must already be up-cased. The algorithm is the same
/// 16-bit rotate-right-by-1 + add as the entry set checksum, but
/// without any byte-skipping, and operates on the LE byte
/// representation of each UTF-16 code unit.
#[must_use]
pub fn compute_name_hash(upcased_name: &[u16]) -> u16 {
    let mut hash: u16 = 0;
    for &ch in upcased_name {
        let [lo, hi] = ch.to_le_bytes();
        let bit0 = if hash & 1 != 0 { 0x8000u16 } else { 0u16 };
        hash = bit0.wrapping_add(hash >> 1).wrapping_add(u16::from(lo));
        let bit0 = if hash & 1 != 0 { 0x8000u16 } else { 0u16 };
        hash = bit0.wrapping_add(hash >> 1).wrapping_add(u16::from(hi));
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Builds a minimal compressed upcase table where only 'a'-'z'
    /// map to 'A'-'Z' and everything else is identity-mapped.
    fn make_test_compressed_table() -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

        // 0x0000..0x0060: identity run of 0x61 chars
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // marker
        data.extend_from_slice(&0x0061u16.to_le_bytes()); // skip 0x61 chars

        // 0x0061..0x007A: 'a'-'z' -> 'A'-'Z' (26 non-identity mappings)
        for i in 0u16..26 {
            data.extend_from_slice(&(0x0041 + i).to_le_bytes());
        }

        // 0x007B..0xFFFF: identity run of 0xFF85 chars
        data.extend_from_slice(&0xFFFFu16.to_le_bytes()); // marker
        data.extend_from_slice(&0xFF85u16.to_le_bytes()); // skip rest

        data
    }

    #[test]
    fn decompress_basic() {
        let compressed = make_test_compressed_table();
        let table = decompress_upcase_table(&compressed).unwrap();
        assert_eq!(table.len(), 65_536);
        // Identity-mapped chars stored as 0
        assert_eq!(table[0x0041], 0); // 'A' -> identity
        // Non-identity mappings
        assert_eq!(table[0x0061], 0x0041); // 'a' -> 'A'
        assert_eq!(table[0x007A], 0x005A); // 'z' -> 'Z'
    }

    #[test]
    fn upcase_identity() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());
        assert_eq!(upt.upcase(0x0041), 0x0041); // 'A' stays 'A'
        assert_eq!(upt.upcase(0x0030), 0x0030); // '0' stays '0'
    }

    #[test]
    fn upcase_lowercase_to_upper() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());
        assert_eq!(upt.upcase(0x0061), 0x0041); // 'a' -> 'A'
        assert_eq!(upt.upcase(0x007A), 0x005A); // 'z' -> 'Z'
    }

    #[test]
    fn checksum_computation() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let cs = compute_upcase_checksum(&data);
        assert_ne!(cs, 0);
        assert_eq!(cs, compute_upcase_checksum(&data)); // deterministic
    }

    #[test]
    fn load_rejects_bad_checksum() {
        let compressed = make_test_compressed_table();
        let result = ExFatUpcaseTable::load(&compressed, 0xDEAD_BEEF);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExFatError::UpcaseChecksumMismatch { .. }
        ));
    }

    #[test]
    fn load_accepts_correct_checksum() {
        let compressed = make_test_compressed_table();
        let correct_checksum = compute_upcase_checksum(&compressed);
        let upt = ExFatUpcaseTable::load(&compressed, correct_checksum).unwrap();
        assert_eq!(upt.upcase(0x0061), 0x0041); // 'a' -> 'A'
    }

    #[test]
    fn compute_name_hash_deterministic() {
        let name: Vec<u16> = "TEST".encode_utf16().collect();
        let h1 = compute_name_hash(&name);
        let h2 = compute_name_hash(&name);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn compute_name_hash_uses_le_bytes() {
        // 'A' = 0x0041, LE bytes = [0x41, 0x00]
        let name = vec![0x0041u16]; // "A"
        let hash = compute_name_hash(&name);
        // Manual: hash=0 -> lo=0x41: ror(0)+0x41=0x0041
        //         hash=0x0041 -> hi=0x00: bit0=1, 0x8000+(0x0041>>1)=0x8020
        assert_eq!(hash, 0x8020);
    }

    #[test]
    fn names_equal_case_insensitive() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());

        let hello: Vec<u16> = "hello".encode_utf16().collect();
        let hello_upper: Vec<u16> = "HELLO".encode_utf16().collect();
        let world: Vec<u16> = "world".encode_utf16().collect();

        assert!(upt.names_equal(&hello, &hello_upper));
        assert!(!upt.names_equal(&hello, &world));
    }

    #[test]
    fn names_equal_different_lengths() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());

        let short: Vec<u16> = "hi".encode_utf16().collect();
        let long: Vec<u16> = "hello".encode_utf16().collect();
        assert!(!upt.names_equal(&short, &long));
    }

    #[test]
    fn name_equals_str_basic() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());

        let name: Vec<u16> = "Test.TXT".encode_utf16().collect();
        assert!(upt.name_equals_str(&name, "test.txt"));
        assert!(upt.name_equals_str(&name, "TEST.TXT"));
        assert!(!upt.name_equals_str(&name, "test.doc"));
    }

    /// After the table is fully decompressed (index reaches 0x10000),
    /// any trailing bytes in the compressed buffer must be ignored.
    /// Mutating `&&` to `||` in the loop guard keeps reading past the
    /// completion point and writes to `table[0x10000]`, which is
    /// out of bounds and panics.
    #[test]
    fn decompress_handles_trailing_bytes_after_complete_table() {
        let mut compressed = make_test_compressed_table();
        compressed.extend_from_slice(&[0xAA, 0xBB]);
        let table = decompress_upcase_table(&compressed)
            .expect("trailing bytes after a complete table must be ignored");
        assert_eq!(table.len(), 65_536);
    }

    /// An odd-length compressed slice cannot form a complete u16
    /// pair on the last iteration. The original guard `i + 1 < len`
    /// exits the loop before the out-of-bounds read. Mutating to
    /// `<=` (or replacing `+` with `*` so the check collapses to
    /// `i < len`) lets the loop attempt `compressed[i+1]` past the
    /// slice and panic.
    #[test]
    fn decompress_rejects_odd_length_partial_pair() {
        let result = decompress_upcase_table(&[0xFF]);
        assert!(
            matches!(result, Err(ExFatError::InvalidUpcaseTable { .. })),
            "incomplete pair must surface as InvalidUpcaseTable, got: {result:?}"
        );
    }

    /// After the loop, an incomplete decompression (index never
    /// reaches 0x10000) must surface as `InvalidUpcaseTable`. The
    /// guard is `index < 0x10000`; mutating `<` to `>` makes the
    /// guard impossible (index can only ever be `<= 0x10000`), so
    /// the function unconditionally returns a partially-zeroed
    /// table. An empty input is the simplest unambiguous case.
    #[test]
    fn decompress_rejects_empty_input() {
        let result = decompress_upcase_table(&[]);
        assert!(
            matches!(result, Err(ExFatError::InvalidUpcaseTable { .. })),
            "empty compressed input must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn name_hash_for_name_case_independent() {
        let compressed = make_test_compressed_table();
        let upt =
            ExFatUpcaseTable::from_decompressed(decompress_upcase_table(&compressed).unwrap());

        let lower: Vec<u16> = "test.txt".encode_utf16().collect();
        let upper: Vec<u16> = "TEST.TXT".encode_utf16().collect();
        let mixed: Vec<u16> = "Test.Txt".encode_utf16().collect();

        let h1 = upt.name_hash_for_name(&lower);
        let h2 = upt.name_hash_for_name(&upper);
        let h3 = upt.name_hash_for_name(&mixed);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }
}
