//! Casefolding for ext4 `CASEFOLD_FL` directories.
//!
//! Non-encrypted casefolded directories hash the casefolded form of
//! the lookup name. The kernel applies `utf8_casefold()` which does
//! NFD normalization + Unicode Simple `CaseFold`.
//!
//! **Default (no_std-safe):** ASCII casefolding only. Non-ASCII
//! names fall back to sequential scan with `eq_ignore_ascii_case`.
//!
//! **With `unicode-casefold` feature:** Full Unicode NFD +
//! `CaseFold` for both sequential-scan comparison *and* htree hashing.
//! `casefold_for_hash` folds non-ASCII names through the same
//! `NFD + Simple/Full CaseFold` pipeline the kernel's `utf8_casefold`
//! applies, so non-ASCII lookups in `CASEFOLD_FL` directories can take
//! the htree fast path. A fold that diverges from the kernel only
//! costs the htree speedup — `htree_lookup` already falls back to
//! sequential scan on a leaf miss — so this can never mis-resolve a
//! name.

use alloc::borrow::Cow;
#[cfg(feature = "unicode-casefold")]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "unicode-casefold")]
use unicode_casefold::UnicodeCaseFold;
#[cfg(feature = "unicode-casefold")]
use unicode_normalization::UnicodeNormalization;

/// Casefold a directory entry name for htree hashing.
///
/// Returns the bytes the kernel's `utf8_casefold()` would hash:
/// - ASCII names are lowercased (borrowed unchanged when already
///   lowercase).
/// - Non-ASCII names require the `unicode-casefold` feature; with it
///   they are folded through `NFD + CaseFold` (matching the kernel's
///   `nfdicf` decomposition). Without the feature — or when the name
///   is not valid UTF-8 — `None` is returned, signalling the caller to
///   fall back to sequential scan.
pub(crate) fn casefold_for_hash(name: &[u8]) -> Option<Cow<'_, [u8]>> {
    if name.iter().all(|&b| b <= 0x7F) {
        // ASCII fast path — no Unicode tables needed.
        if name.iter().all(|&b| !b.is_ascii_uppercase()) {
            return Some(Cow::Borrowed(name));
        }
        let mut result = Vec::with_capacity(name.len());
        for &b in name {
            result.push(b.to_ascii_lowercase());
        }
        return Some(Cow::Owned(result));
    }

    // Non-ASCII: fold through the Unicode NFD + CaseFold pipeline.
    #[cfg(feature = "unicode-casefold")]
    {
        let name_str = core::str::from_utf8(name).ok()?;
        Some(Cow::Owned(unicode_casefold_string(name_str).into_bytes()))
    }
    #[cfg(not(feature = "unicode-casefold"))]
    {
        None
    }
}

/// Prepared lookup key for matching names in a `CASEFOLD_FL` directory.
///
/// The query is normalized once per lookup so repeated candidate
/// comparisons do not need to rebuild the same folded form.
pub(crate) enum PreparedLookupName<'a> {
    Exact(&'a [u8]),
    #[cfg(not(feature = "unicode-casefold"))]
    AsciiCasefold(&'a [u8]),
    #[cfg(feature = "unicode-casefold")]
    UnicodeCasefold {
        ascii_query: Option<&'a [u8]>,
        folded_query: String,
    },
}

impl PreparedLookupName<'_> {
    pub(crate) fn matches(&self, candidate: &[u8]) -> bool {
        match self {
            Self::Exact(query) => candidate == *query,
            #[cfg(not(feature = "unicode-casefold"))]
            Self::AsciiCasefold(query) => candidate.eq_ignore_ascii_case(query),
            #[cfg(feature = "unicode-casefold")]
            Self::UnicodeCasefold {
                ascii_query,
                folded_query,
            } => {
                if let Some(query) = ascii_query
                    && candidate.is_ascii()
                {
                    candidate.eq_ignore_ascii_case(query)
                } else {
                    unicode_casefold_matches(candidate, folded_query)
                }
            }
        }
    }
}

/// Prepare a reusable lookup key for repeated directory-entry matching.
pub(crate) fn prepare_lookup_name(name: &[u8], casefold: bool) -> PreparedLookupName<'_> {
    if !casefold {
        return PreparedLookupName::Exact(name);
    }

    #[cfg(feature = "unicode-casefold")]
    {
        if let Ok(name_str) = core::str::from_utf8(name) {
            PreparedLookupName::UnicodeCasefold {
                ascii_query: name.is_ascii().then_some(name),
                folded_query: unicode_casefold_string(name_str),
            }
        } else {
            PreparedLookupName::Exact(name)
        }
    }
    #[cfg(not(feature = "unicode-casefold"))]
    {
        PreparedLookupName::AsciiCasefold(name)
    }
}

/// Compare two names for case-insensitive equality in a `CASEFOLD_FL`
/// directory.
///
/// Without the `unicode-casefold` feature, uses ASCII case-insensitive
/// comparison. With the feature, uses Unicode NFD normalization +
/// `CaseFold` for proper UTF-8 handling.
#[cfg(test)]
pub(crate) fn casefold_eq(a: &[u8], b: &[u8]) -> bool {
    prepare_lookup_name(b, true).matches(a)
}

/// Unicode NFD + `CaseFold` equality comparison.
///
/// Both inputs are treated as UTF-8. Invalid UTF-8 sequences fall
/// back to byte-exact comparison (a non-matching pair of invalid
/// sequences will never falsely match).
#[cfg(feature = "unicode-casefold")]
fn unicode_casefold_string(name: &str) -> String {
    name.nfd().case_fold().collect()
}

/// Compare a candidate entry against a pre-folded Unicode query.
#[cfg(feature = "unicode-casefold")]
fn unicode_casefold_matches(candidate: &[u8], query: &str) -> bool {
    let Ok(candidate_str) = core::str::from_utf8(candidate) else {
        return false;
    };

    candidate_str.nfd().case_fold().eq(query.chars())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- casefold_for_hash tests ---

    #[test]
    fn hash_ascii_lowercased() {
        let result = casefold_for_hash(b"Hello.TXT").unwrap();
        assert_eq!(&*result, b"hello.txt");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn hash_already_lowercase_borrows() {
        let result = casefold_for_hash(b"readme.md").unwrap();
        assert_eq!(&*result, b"readme.md");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[cfg(not(feature = "unicode-casefold"))]
    #[test]
    fn hash_non_ascii_returns_none_without_feature() {
        // Without the Unicode tables, non-ASCII names bail to
        // sequential scan.
        assert!(casefold_for_hash("café".as_bytes()).is_none());
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn hash_non_ascii_invalid_utf8_returns_none() {
        // Even with the feature, a name that is not valid UTF-8 cannot
        // be folded — bail to sequential scan.
        assert!(casefold_for_hash(&[0xFF, 0xFE, 0x80]).is_none());
    }

    /// Every name in a `CASEFOLD_FL` directory hashes the *folded* form,
    /// so any two names that the kernel treats as equal must produce
    /// byte-identical `casefold_for_hash` output. These pairs span the
    /// Unicode edge cases the issue calls out: combining marks,
    /// precomposed vs decomposed, German sharp-s, Greek final sigma,
    /// Turkish dotted/dotless I, Cyrillic, and fullwidth forms.
    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn hash_folds_case_and_normalization_variants_identically() {
        // (a, b) — distinct byte strings the kernel folds to one key.
        let equal_pairs: &[(&str, &str)] = &[
            // Latin-1 precomposed accents, upper vs lower.
            ("café", "CAFÉ"),
            ("café", "Café"),
            ("àÀâÂäÄ", "ààââää"),
            ("éÉèÈêÊëË", "ééèèêêëë"),
            ("ÿÝ", "ÿý"),
            ("ñÑ", "ññ"),
            ("çÇ", "çç"),
            ("œŒ", "œœ"),
            ("åÅ", "åå"),
            ("øØ", "øø"),
            // Precomposed vs canonical decomposition (NFD).
            ("café", "cafe\u{0301}"),
            ("CAFÉ", "CAFE\u{0301}"),
            ("ñ", "n\u{0303}"),
            ("Å", "A\u{030A}"),
            ("ô", "o\u{0302}"),
            ("ü", "u\u{0308}"),
            ("ī", "i\u{0304}"),
            ("ḅ", "b\u{0323}"),
            // German sharp-s — full casefold to "ss".
            ("straße", "STRASSE"),
            ("straße", "Strasse"),
            ("groß", "GROSS"),
            ("ß", "ss"),
            // Greek — final sigma folds to medial sigma.
            ("ΟΔΟΣ", "οδος"),
            ("ὈΔΥΣΣΕΎΣ", "ὀδυσσεύς"),
            ("Σίσυφος", "σίσυφος"),
            ("ΑΒΓΔΕ", "αβγδε"),
            ("ΖΗΘΙΚ", "ζηθικ"),
            ("ΛΜΝΞΟ", "λμνξο"),
            ("ΠΡΣΤΥ", "πρστυ"),
            ("ΦΧΨΩ", "φχψω"),
            ("Ή", "ή"),
            ("Ί", "ί"),
            // Cyrillic.
            ("ПРИВЕТ", "привет"),
            ("Москва", "москва"),
            ("ЁЖИК", "ёжик"),
            ("АБВГД", "абвгд"),
            ("ЕЖЗИЙ", "ежзий"),
            ("КЛМНО", "клмно"),
            ("ПРСТУ", "прсту"),
            ("ФХЦЧШ", "фхцчш"),
            ("ЩЪЫЬЭ", "щъыьэ"),
            ("ЮЯ", "юя"),
            // Turkish I — standard (non-Turkic) casefold: I → i.
            ("İSTANBUL", "i\u{0307}stanbul"),
            ("DİYARBAKIR", "di\u{0307}yarbakir"),
            // Latin Extended-A.
            ("ĀĂĄ", "āăą"),
            ("ĆĈĊČ", "ćĉċč"),
            ("ĎĐ", "ďđ"),
            ("ŁŃŅŇ", "łńņň"),
            ("ŐŒ", "őœ"),
            ("ŠŞŜ", "šşŝ"),
            ("ŻŹŽ", "żźž"),
            ("ǍǏǑǓ", "ǎǐǒǔ"),
            // Armenian and Georgian (Georgian has no case).
            ("ԱԲԳ", "աբգ"),
            ("ԴԵԶ", "դեզ"),
        ];
        for (a, b) in equal_pairs {
            let fa = casefold_for_hash(a.as_bytes()).expect("fold a");
            let fb = casefold_for_hash(b.as_bytes()).expect("fold b");
            assert_eq!(
                &*fa, &*fb,
                "casefold_for_hash must collapse {a:?} and {b:?} to one key",
            );
        }
        assert!(
            equal_pairs.len() >= 50,
            "issue #122 wants >= 50 Unicode-edge names",
        );
    }

    /// Exact-output spot checks for the well-known folds.
    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn hash_known_fold_outputs() {
        // Full casefold of sharp-s.
        assert_eq!(&*casefold_for_hash("ß".as_bytes()).unwrap(), b"ss");
        // NFD decomposes the precomposed accent; casefold lowercases.
        assert_eq!(
            &*casefold_for_hash("É".as_bytes()).unwrap(),
            "e\u{0301}".as_bytes(),
        );
        // Greek final sigma ς (U+03C2) folds to medial sigma σ (U+03C3).
        assert_eq!(&*casefold_for_hash("ς".as_bytes()).unwrap(), "σ".as_bytes(),);
        // A pure-ASCII name still takes the borrowed fast path.
        assert!(matches!(
            casefold_for_hash(b"plain.txt"),
            Some(Cow::Borrowed(_)),
        ));
    }

    /// Distinct names must *not* collapse — folding is case/normalization
    /// insensitive, not lossy.
    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn hash_keeps_distinct_names_distinct() {
        let distinct: &[(&str, &str)] = &[
            ("café", "cafés"),
            ("straße", "strasbourg"),
            ("Москва", "москве"),
            ("αβγ", "αβδ"),
            ("über", "uber"),
        ];
        for (a, b) in distinct {
            let fa = casefold_for_hash(a.as_bytes()).expect("fold a");
            let fb = casefold_for_hash(b.as_bytes()).expect("fold b");
            assert_ne!(&*fa, &*fb, "{a:?} and {b:?} must fold distinctly");
        }
    }

    #[test]
    fn hash_empty_borrows() {
        let result = casefold_for_hash(b"").unwrap();
        assert_eq!(&*result, b"");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn hash_digits_borrow() {
        let result = casefold_for_hash(b"123_test.log").unwrap();
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // --- casefold_eq tests ---

    #[test]
    fn eq_ascii_case_insensitive() {
        assert!(casefold_eq(b"Hello.TXT", b"hello.txt"));
        assert!(casefold_eq(b"readme.md", b"README.MD"));
        assert!(!casefold_eq(b"hello.txt", b"other.txt"));
    }

    #[test]
    fn eq_exact_match() {
        assert!(casefold_eq(b"same", b"same"));
    }

    #[test]
    fn prepared_lookup_ascii_casefold_matches_without_rebuilding_query() {
        let prepared = prepare_lookup_name(b"README.MD", true);
        assert!(prepared.matches(b"readme.md"));
        assert!(!prepared.matches(b"other.md"));
    }

    #[test]
    fn eq_different_length() {
        assert!(!casefold_eq(b"short", b"longer"));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn eq_unicode_german_sharp_s() {
        // German sharp s: ß (U+00DF) folds to "ss"
        assert!(casefold_eq("straße".as_bytes(), "STRASSE".as_bytes()));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn prepared_lookup_unicode_casefold_matches_multiple_candidates() {
        let prepared = prepare_lookup_name("straße".as_bytes(), true);
        assert!(prepared.matches("STRASSE".as_bytes()));
        assert!(prepared.matches("Straße".as_bytes()));
        assert!(!prepared.matches("strasbourg".as_bytes()));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn eq_unicode_accented() {
        // é as precomposed (U+00E9) vs É (U+00C9)
        assert!(casefold_eq("café".as_bytes(), "CAFÉ".as_bytes()));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn eq_unicode_nfd_composed_vs_decomposed() {
        // é as precomposed (U+00E9) vs decomposed (e + U+0301)
        let composed = "café";
        let decomposed = "cafe\u{0301}";
        assert!(casefold_eq(composed.as_bytes(), decomposed.as_bytes()));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn eq_unicode_invalid_utf8_falls_back() {
        // Invalid UTF-8: should fall back to byte comparison
        let bad = &[0xFF, 0xFE];
        assert!(casefold_eq(bad, bad));
        assert!(!casefold_eq(bad, &[0xFF, 0xFD]));
    }

    #[cfg(feature = "unicode-casefold")]
    #[test]
    fn eq_unicode_turkish_not_special() {
        // We use non-Turkic locale (standard Unicode casefold).
        // I (U+0049) folds to i (U+0069), not ı (U+0131).
        assert!(casefold_eq(b"I", b"i"));
    }
}
