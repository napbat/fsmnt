//! APFS directory-name hashing and Unicode-aware name folding.
//!
//! A directory-entry key on a case-insensitive or normalization-insensitive
//! volume (`j_drec_hashed_key_t`) carries a precomputed hash of the name.
//! The hash is a CRC-32C over the name after Unicode normalization (NFD)
//! and, on case-insensitive volumes, case folding — letting a lookup find
//! an entry without normalizing every name in the directory.
//!
//! Normalization (NFD) is exact: Unicode's Normalization Stability Policy
//! freezes every canonical decomposition, so the `unicode-normalization`
//! crate matches Apple's Unicode-10 tables for all assigned code points.
//! Case folding here is `char::to_lowercase`, which is *conservative* —
//! it never reports two distinct names as equal, so its only failure mode
//! is missing a match for the few code points where Unicode case folding
//! differs from lowercasing (`ß`/`ss`, the `ﬀ` ligatures, `İ`). Apple's
//! exact fold table is GPL-licensed and cannot be vendored here.
//!
//! apfs-fuse `ApfsLib/Util.cpp` (`HashFilename`), `ApfsLib/Crc32.cpp`.

use alloc::vec::Vec;

use unicode_normalization::UnicodeNormalization;

use crate::directory::{J_DREC_HASH_SHIFT, J_DREC_LEN_MASK};

/// Reflected CRC-32C polynomial (`0x1EDC6F41` bit-reversed) — the
/// polynomial APFS hashes directory names with (apfs-fuse `Util.cpp:44`).
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Computes the APFS directory-name CRC-32C over `data`.
///
/// Reflected, initialized to `0xFFFFFFFF`, with **no** final XOR — APFS
/// uses the raw register value (apfs-fuse `Crc32::GetCRC`).
fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Normalizes `name` to NFD and, when `case_fold` is set, case-folds it,
/// returning the resulting code-point sequence.
///
/// This is the canonical form APFS hashes and compares; the hash and the
/// fallback comparison in [`crate::directory`] both go through it, so they
/// always agree.
#[must_use]
pub fn normalize_fold(name: &str, case_fold: bool) -> Vec<char> {
    let mut out = Vec::new();
    for ch in name.nfd() {
        if case_fold {
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Computes the `name_len_and_hash` field of a `j_drec_hashed_key_t` for
/// `name`, case-folding when `case_fold` is set.
///
/// The result packs the 22-bit name hash in the high bits and the stored
/// name length — the UTF-8 byte length plus the trailing NUL — in the low
/// ten bits (apfs-fuse `Util.cpp:277`).
#[must_use]
pub fn name_hash(name: &str, case_fold: bool) -> u32 {
    let normalized = normalize_fold(name, case_fold);
    // The CRC runs over the code points as little-endian 32-bit values.
    let mut bytes = Vec::with_capacity(normalized.len() * 4);
    for ch in normalized {
        bytes.extend_from_slice(&(ch as u32).to_le_bytes());
    }
    let hash = crc32c(&bytes) & 0x003F_FFFF;
    // The stored name length includes the trailing NUL.
    let name_len = (name.len() as u32 + 1) & J_DREC_LEN_MASK;
    pack_hash_len(hash, name_len)
}

/// Packs a 22-bit hash into the high bits and a 10-bit length into the low
/// bits of a `j_drec_hashed_key_t::name_len_and_hash` field. The two fields
/// occupy disjoint bit ranges, so `|` and `^` produce the same value here —
/// the `mutants::skip` below acknowledges that equivalence.
#[cfg_attr(test, mutants::skip)]
fn pack_hash_len(hash: u32, name_len: u32) -> u32 {
    (hash << J_DREC_HASH_SHIFT) | name_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_the_standard_check_vector() {
        // The CRC-32C check value of "123456789" is 0xE3069283 once the
        // final XOR is applied; crc32c() omits that XOR, as APFS does.
        assert_eq!(crc32c(b"123456789") ^ 0xFFFF_FFFF, 0xE306_9283);
    }

    #[test]
    fn normalize_fold_lowercases_ascii_when_folding() {
        assert_eq!(
            normalize_fold("ReadMe", true),
            vec!['r', 'e', 'a', 'd', 'm', 'e']
        );
        assert_eq!(
            normalize_fold("ReadMe", false),
            vec!['R', 'e', 'a', 'd', 'M', 'e']
        );
    }

    #[test]
    fn normalize_fold_decomposes_a_precomposed_accent() {
        // U+00E9 (é) decomposes to 'e' + U+0301 (combining acute accent).
        assert_eq!(normalize_fold("\u{00E9}", false), vec!['e', '\u{0301}']);
    }

    #[test]
    fn name_hash_packs_the_name_length() {
        // The low ten bits hold the UTF-8 length plus the NUL.
        let packed = name_hash("file.txt", false);
        assert_eq!(packed & J_DREC_LEN_MASK, "file.txt".len() as u32 + 1);
    }

    #[test]
    fn name_hash_folds_case_when_requested() {
        // Case variants collide only under case folding.
        assert_eq!(name_hash("Photos", true), name_hash("photos", true));
        assert_ne!(name_hash("Photos", false), name_hash("photos", false));
    }

    #[test]
    fn name_hash_matches_known_reference_vectors() {
        // Computed against the unmutated `crc32c() & 0x003F_FFFF` mask, so
        // a mutation that flips `&` to `^` (or otherwise perturbs the low
        // 22 bits) changes these absolute values. Inputs span ASCII and
        // a typical filename so the hashes cover non-trivial bit patterns.
        assert_eq!(name_hash("a", false), 0x7957_B002);
        assert_eq!(name_hash("ReadMe", false), 0x966F_A007);
        assert_eq!(name_hash("file.txt", false), 0x03C1_7C09);
    }

    #[test]
    fn name_hash_matches_an_nfc_and_nfd_spelling() {
        // Precomposed "café" and decomposed "cafe\u{0301}" normalize alike,
        // so their hash bits agree even though the stored byte lengths —
        // and thus the packed length bits — differ.
        assert_eq!(
            name_hash("caf\u{00E9}", false) >> J_DREC_HASH_SHIFT,
            name_hash("cafe\u{0301}", false) >> J_DREC_HASH_SHIFT,
        );
    }
}
