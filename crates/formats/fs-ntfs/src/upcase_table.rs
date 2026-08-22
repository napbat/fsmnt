use core::cmp::Ordering;
use core::mem;

use alloc::vec;
use alloc::vec::Vec;
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use fsmnt_parser_core::io::FsReadSeek;

/// The Upcase Table contains an uppercase character for each Unicode character of the Basic Multilingual Plane.
const UPCASE_CHARACTER_COUNT: usize = 65536;

/// Hence, the table has a size of 128 KiB.
const UPCASE_TABLE_SIZE: usize = UPCASE_CHARACTER_COUNT * mem::size_of::<u16>();
const UPCASE_TABLE_SIZE_U64: u64 = 65_536 * 2;

/// Manages a table for converting characters to uppercase.
/// This table is used for case-insensitive file name comparisons.
///
/// NTFS stores such a table in the special $`UpCase` file on every filesystem.
/// As this table is slightly different depending on the Windows version used for creating the filesystem,
/// it is very important to always read the table from the filesystem itself.
/// Hence, this table is not hardcoded into the crate.
#[derive(Clone, Debug)]
pub(crate) struct UpcaseTable {
    uppercase_characters: Vec<u16>,
}

impl UpcaseTable {
    /// Reads the $`UpCase` file from the given filesystem into a new [`UpcaseTable`] object.
    pub(crate) fn read<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        // Lookup the $UpCase file and its $DATA attribute.
        let upcase_file = ntfs.file(fs, KnownNtfsFileRecordNumber::UpCase.as_u64())?;
        let data_item = upcase_file
            .data(fs, "")
            .ok_or(NtfsError::AttributeNotFound {
                position: upcase_file.position(),
                ty: NtfsAttributeType::Data,
            })??;

        let data_attribute = data_item.to_attribute()?;
        if data_attribute.value_length() != UPCASE_TABLE_SIZE_U64 {
            return Err(NtfsError::InvalidUpcaseTableSize {
                expected: UPCASE_TABLE_SIZE_U64,
                actual: data_attribute.value_length(),
            });
        }

        // Read the entire raw data from the $DATA attribute.
        let mut data_value = data_attribute.value(fs)?;
        let mut data = vec![0u8; UPCASE_TABLE_SIZE];
        data_value.read_exact(fs, &mut data)?;

        // Store it in an array of `u16` uppercase characters.
        // Any endianness conversion is done here once, which makes `u16_to_uppercase` fast.
        let uppercase_characters = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|two_bytes| u16::from_le_bytes(*two_bytes))
            .collect();

        Ok(Self {
            uppercase_characters,
        })
    }

    /// Returns the uppercase variant of the given UCS-2 character (i.e. a Unicode character
    /// from the Basic Multilingual Plane) based on the stored conversion table.
    /// A character without an uppercase equivalent is returned as-is.
    pub(crate) fn u16_to_uppercase(&self, character: u16) -> u16 {
        self.uppercase_characters[usize::from(character)]
    }
}

/// Trait for a case-insensitive ordering with respect to the $`UpCase` table read from the filesystem.
pub trait UpcaseOrd<Rhs> {
    /// Performs a case-insensitive ordering based on the $`UpCase` table read from the filesystem.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called on the passed [`Ntfs`] object.
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &Rhs) -> Ordering;
}

impl<'a> UpcaseOrd<U16StrLe<'a>> for U16StrLe<'_> {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &U16StrLe<'a>) -> Ordering {
        upcase_cmp_iter(self.u16_iter(), other.u16_iter(), ntfs)
    }
}

impl UpcaseOrd<&str> for U16StrLe<'_> {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &&str) -> Ordering {
        upcase_cmp_iter(self.u16_iter(), other.encode_utf16(), ntfs)
    }
}

impl<'a> UpcaseOrd<U16StrLe<'a>> for &str {
    fn upcase_cmp(&self, ntfs: &Ntfs, other: &U16StrLe<'a>) -> Ordering {
        upcase_cmp_iter(self.encode_utf16(), other.u16_iter(), ntfs)
    }
}

fn upcase_cmp_iter<TI, OI>(mut this_iter: TI, mut other_iter: OI, ntfs: &Ntfs) -> Ordering
where
    TI: Iterator<Item = u16>,
    OI: Iterator<Item = u16>,
{
    let upcase_table = ntfs.upcase_table();

    loop {
        match (this_iter.next(), other_iter.next()) {
            (Some(this_code_unit), Some(other_code_unit)) => {
                // We have two UTF-16 code units to compare.
                let this_upper = upcase_table.u16_to_uppercase(this_code_unit);
                let other_upper = upcase_table.u16_to_uppercase(other_code_unit);

                if this_upper != other_upper {
                    return this_upper.cmp(&other_upper);
                }
            }
            (Some(_), None) => {
                // `this_iter` is longer than `other_iter` but otherwise equal.
                return Ordering::Greater;
            }
            (None, Some(_)) => {
                // `other_iter` is longer than `this_iter` but otherwise equal.
                return Ordering::Less;
            }
            (None, None) => {
                // We made it to the end of both strings, so they must be equal.
                return Ordering::Equal;
            }
        }
    }
}

/// Trait for case-sensitive ordering of UTF-16 strings.
///
/// This is used for POSIX namespace filenames in NTFS, which are case-sensitive
/// unlike the default Win32/DOS namespaces.
pub trait CaseSensitiveOrd<Rhs> {
    /// Performs a case-sensitive ordering comparison.
    fn case_sensitive_cmp(&self, other: &Rhs) -> Ordering;
}

impl<'a> CaseSensitiveOrd<U16StrLe<'a>> for U16StrLe<'_> {
    fn case_sensitive_cmp(&self, other: &U16StrLe<'a>) -> Ordering {
        case_sensitive_cmp_iter(self.u16_iter(), other.u16_iter())
    }
}

impl CaseSensitiveOrd<&str> for U16StrLe<'_> {
    fn case_sensitive_cmp(&self, other: &&str) -> Ordering {
        case_sensitive_cmp_iter(self.u16_iter(), other.encode_utf16())
    }
}

impl<'a> CaseSensitiveOrd<U16StrLe<'a>> for &str {
    fn case_sensitive_cmp(&self, other: &U16StrLe<'a>) -> Ordering {
        case_sensitive_cmp_iter(self.encode_utf16(), other.u16_iter())
    }
}

fn case_sensitive_cmp_iter<TI, OI>(mut this_iter: TI, mut other_iter: OI) -> Ordering
where
    TI: Iterator<Item = u16>,
    OI: Iterator<Item = u16>,
{
    loop {
        match (this_iter.next(), other_iter.next()) {
            (Some(this_code_unit), Some(other_code_unit)) => {
                // Compare UTF-16 code units directly (case-sensitive).
                if this_code_unit != other_code_unit {
                    return this_code_unit.cmp(&other_code_unit);
                }
            }
            (Some(_), None) => {
                // `this_iter` is longer than `other_iter` but otherwise equal.
                return Ordering::Greater;
            }
            (None, Some(_)) => {
                // `other_iter` is longer than `this_iter` but otherwise equal.
                return Ordering::Less;
            }
            (None, None) => {
                // We made it to the end of both strings, so they must be equal.
                return Ordering::Equal;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an [`UpcaseTable`] that maps every code unit to itself,
    /// except ASCII lowercase letters which map to their uppercase form.
    fn ascii_upcase_table() -> UpcaseTable {
        let mut chars: Vec<u16> = (0u32..u32::try_from(UPCASE_CHARACTER_COUNT)
            .expect("test value fits u32"))
            .map(|c| u16::try_from(c).expect("test value fits u16"))
            .collect();
        for c in b'a'..=b'z' {
            chars[usize::from(c)] = u16::from(c - 32);
        }
        UpcaseTable {
            uppercase_characters: chars,
        }
    }

    #[test]
    fn test_upcase_table() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let upcase_table = UpcaseTable::read(&ntfs, &mut testfs1).unwrap();

        // Prove that at least the lowercase English characters are mapped to their uppercase equivalents.
        // It makes no sense to check everything here.
        for (lowercase, uppercase) in (b'a'..=b'z').zip(b'A'..=b'Z') {
            assert_eq!(
                upcase_table.u16_to_uppercase(u16::from(lowercase)),
                u16::from(uppercase)
            );
        }
    }

    #[test]
    fn upcase_table_size_constant() {
        // 65536 code points * 2 bytes each = 131072 (line 19). A `+` or
        // `/` mutation would yield 65538 or 32768.
        assert_eq!(UPCASE_TABLE_SIZE, 131_072);
    }

    #[test]
    fn u16_to_uppercase_maps_per_table() {
        // u16_to_uppercase indexes into the stored table (line 77): the
        // genuine mapping is distinct from the 0/1 return replacements.
        let table = ascii_upcase_table();
        assert_eq!(table.u16_to_uppercase(u16::from(b'a')), u16::from(b'A'));
        assert_eq!(table.u16_to_uppercase(u16::from(b'z')), u16::from(b'Z'));
        // A character with no uppercase equivalent maps to itself.
        assert_eq!(table.u16_to_uppercase(0x0041), 0x0041); // 'A'
        assert_eq!(table.u16_to_uppercase(0x2603), 0x2603); // snowman
    }

    /// Encode an ASCII string as UTF-16LE bytes for `U16StrLe`.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn upcase_cmp_iter_case_insensitive() {
        // upcase_cmp_iter compares uppercased code units (line 123 `!=`):
        // equal-when-uppercased strings compare Equal; differing ones do
        // not. With `==` instead of `!=` the loop would early-return on the
        // first matching pair, breaking ordering.
        let ntfs = Ntfs::with_upcase_table_for_test(ascii_upcase_table());

        let abc = utf16le("abc");
        let upper_abc = utf16le("ABC");
        let abd = utf16le("abd");
        let bxx = utf16le("bxx");

        // "abc" vs "ABC" are equal case-insensitively.
        assert_eq!(
            "abc".upcase_cmp(&ntfs, &U16StrLe(&upper_abc)),
            Ordering::Equal
        );
        // "ABC" < "abd" (differ at last unit: 'C' < 'D').
        assert_eq!("ABC".upcase_cmp(&ntfs, &U16StrLe(&abd)), Ordering::Less);
        // Reversed via the U16StrLe self side: "abd" > "ABC".
        assert_eq!(U16StrLe(&abd).upcase_cmp(&ntfs, &"ABC"), Ordering::Greater);
        // First unit differs: 'A' < 'B'.
        assert_eq!(
            U16StrLe(&abc).upcase_cmp(&ntfs, &U16StrLe(&bxx)),
            Ordering::Less
        );
    }

    #[test]
    fn case_sensitive_cmp_iter_distinguishes_case() {
        // case_sensitive_cmp_iter compares raw code units (line 179 `!=`):
        // identical strings are Equal, case differences are not.
        let abc = utf16le("abc");
        let cap_abc = utf16le("Abc");
        let abd = utf16le("abd");

        assert_eq!("abc".case_sensitive_cmp(&U16StrLe(&abc)), Ordering::Equal);
        // Lowercase 'a' (0x61) > uppercase 'A' (0x41).
        assert_eq!(
            "abc".case_sensitive_cmp(&U16StrLe(&cap_abc)),
            Ordering::Greater
        );
        assert_eq!(
            U16StrLe(&cap_abc).case_sensitive_cmp(&"abc"),
            Ordering::Less
        );
        // Differ at last unit.
        assert_eq!(
            U16StrLe(&abc).case_sensitive_cmp(&U16StrLe(&abd)),
            Ordering::Less
        );
    }
}
