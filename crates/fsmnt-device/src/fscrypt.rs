//! fscrypt master keys carried to a filesystem driver.
//!
//! fscrypt is Linux's file-based encryption — the VFS facility ext4, f2fs,
//! UBIFS and Ceph all share, and what Android calls FBE. It leaves the
//! filesystem itself perfectly readable: the directory tree, the sizes and
//! the timestamps are all plaintext. What stays ciphertext is the
//! *contents* of encrypted files and the *names* inside encrypted
//! directories, and the master key that unlocks them is deliberately not on
//! the volume. An operator therefore supplies it out of band, and
//! [`FscryptKeySpec`] is how one key travels from the command line to the
//! driver that opens the volume.
//!
//! The specs are inert here: this crate ships no filesystem parser, so it
//! neither derives identifiers nor validates a key against a policy. It
//! carries the bytes (in a [`Zeroizing`] buffer, and out of every `Debug`
//! output) and states the grammar an operator types.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use zeroize::Zeroizing;

/// Shortest master key the kernel accepts (`FSCRYPT_MIN_KEY_SIZE`).
const MIN_KEY_BYTES: usize = 16;
/// Longest master key the kernel accepts (`FSCRYPT_MAX_KEY_SIZE`).
const MAX_KEY_BYTES: usize = 64;
/// Length a v1 master key must have to be usable at all: the v1 key
/// derivation slices the master key down to the per-file key size, and
/// AES-256-XTS asks for 64 bytes of it.
const V1_KEY_BYTES: usize = 64;
/// Length of a v1 master-key descriptor (`fscrypt_context_v1`).
const DESCRIPTOR_BYTES: usize = 8;

/// One fscrypt master key, as an operator states it.
///
/// The two variants mirror the two policy versions, which differ in how a
/// key is *named*. A v1 policy stores an operator-chosen 8-byte descriptor,
/// so the key cannot be matched to the policy without being told which
/// descriptor it answers to. A v2 policy stores a 16-byte identifier the
/// kernel derives from the key itself (HKDF-SHA512), so a v2 key needs no
/// naming at all — registering it is enough for the driver to work out
/// which policies it unlocks.
///
/// # Textual grammar
///
/// [`FromStr`] accepts, with `<HEX>` being lowercase or uppercase hex
/// digits and `@<PATH>` reading the raw key bytes from a file instead:
///
/// | spec | meaning |
/// | ---- | ------- |
/// | `<HEX>` or `v2:<HEX>` | a v2 master key, 16–64 bytes (32–128 hex digits) |
/// | `v1:<DESCRIPTOR>:<HEX>` | a v1 master key, where `DESCRIPTOR` is 16 hex digits (8 bytes) |
/// | `@<PATH>`, `v2:@<PATH>`, `v1:<DESCRIPTOR>:@<PATH>` | the same, with the key read as raw bytes from `PATH` |
///
/// `Debug` prints key *lengths* and the descriptor, never key bytes, so a
/// spec can sit inside a struct that is logged.
#[derive(Clone, Eq, PartialEq)]
pub enum FscryptKeySpec {
    /// A v1 master key together with the descriptor its policies name.
    V1 {
        /// `master_key_descriptor` the encrypted directories refer to.
        descriptor: [u8; DESCRIPTOR_BYTES],
        /// Raw master-key bytes.
        key: Zeroizing<Vec<u8>>,
    },
    /// A v2 master key. Its identifier is derived from the key, so the
    /// operator does not state one.
    V2 {
        /// Raw master-key bytes.
        key: Zeroizing<Vec<u8>>,
    },
}

impl FscryptKeySpec {
    /// A v1 master key answering to `descriptor`.
    #[must_use]
    pub fn v1(descriptor: [u8; DESCRIPTOR_BYTES], key: Vec<u8>) -> Self {
        Self::V1 {
            descriptor,
            key: Zeroizing::new(key),
        }
    }

    /// A v2 master key, whose identifier the filesystem derives.
    #[must_use]
    pub fn v2(key: Vec<u8>) -> Self {
        Self::V2 {
            key: Zeroizing::new(key),
        }
    }

    /// The raw master-key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        match self {
            Self::V1 { key, .. } | Self::V2 { key } => key,
        }
    }

    /// The v1 descriptor this key answers to, or `None` for a v2 key.
    #[must_use]
    pub fn descriptor(&self) -> Option<[u8; DESCRIPTOR_BYTES]> {
        match self {
            Self::V1 { descriptor, .. } => Some(*descriptor),
            Self::V2 { .. } => None,
        }
    }

    /// `"v1"` or `"v2"`, for messages that name which policy version a
    /// spec was written for.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        match self {
            Self::V1 { .. } => "v1",
            Self::V2 { .. } => "v2",
        }
    }
}

/// Redacted deliberately: these values end up inside
/// [`FilesystemOpenOptions`](crate::FilesystemOpenOptions), which is logged
/// whole in places, and a master key printed once into a log file outlives
/// every other precaution taken with it.
impl fmt::Debug for FscryptKeySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 { descriptor, key } => formatter
                .debug_struct("FscryptKeySpec::V1")
                .field("descriptor", &hex(descriptor))
                .field("key_bytes", &key.len())
                .finish(),
            Self::V2 { key } => formatter
                .debug_struct("FscryptKeySpec::V2")
                .field("key_bytes", &key.len())
                .finish(),
        }
    }
}

/// Lowercase hex, for descriptors and identifiers (never for key bytes).
fn hex(bytes: &[u8]) -> String {
    use fmt::Write;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

/// Why a textual [`FscryptKeySpec`] could not be read.
///
/// Each variant names the part of the grammar that was violated rather than
/// echoing what was typed: the spec carries key material, and an error
/// message is the one place it must not end up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FscryptKeySpecParseError {
    /// A `v1:` spec stopped before its key.
    #[error(
        "a v1 fscrypt key is spelled v1:<DESCRIPTOR>:<KEY>, with a 16-hex-digit descriptor and \
         the key as hex digits or @PATH"
    )]
    V1MissingKey,
    /// The descriptor was not 16 hex digits.
    #[error("v1 key descriptor must be 16 hex digits (8 bytes), not {found}")]
    Descriptor {
        /// Descriptor text as typed, or its length when it was too long to
        /// be a mistyped descriptor. A descriptor is stored in the on-disk
        /// policy, so echoing one discloses nothing the volume does not —
        /// but a key typed into the descriptor's place would be a different
        /// matter, which is what the length limit guards against.
        found: String,
    },
    /// A hex key had an odd number of digits.
    #[error("a hex key needs an even number of digits ({digits} supplied)")]
    OddHex {
        /// How many digits were supplied.
        digits: usize,
    },
    /// A hex key contained something that is not a hex digit.
    #[error(
        "the key must be hex digits (or @PATH to read raw key bytes from a file); the character \
         at position {position} is not one"
    )]
    NotHex {
        /// Zero-based position of the offending character.
        position: usize,
    },
    /// The key was outside the length range fscrypt accepts.
    #[error("key must be 16–64 bytes; {found} supplied")]
    KeyLength {
        /// Length that was supplied.
        found: usize,
    },
    /// A v1 key was shorter than v1 key derivation can use.
    #[error(
        "v1 master keys must be at least 64 bytes (v1 derivation slices the master key down to \
         the 64-byte AES-256-XTS per-file key); {found} supplied"
    )]
    V1KeyLength {
        /// Length that was supplied.
        found: usize,
    },
    /// The `@PATH` form named a file that could not be read.
    #[error("cannot read the fscrypt key from {path:?}: {source}")]
    KeyFile {
        /// Path that was named.
        path: PathBuf,
        /// Why reading it failed.
        #[source]
        source: std::io::Error,
    },
}

impl FromStr for FscryptKeySpec {
    type Err = FscryptKeySpecParseError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        // The v1 form is the only one with structure before the key, and
        // its descriptor cannot contain a colon — so splitting once is
        // enough, and everything after the second colon is the key, which
        // leaves Windows paths (`@C:\keys\ce.key`) intact.
        if let Some(rest) = spec.strip_prefix("v1:") {
            let (descriptor, key) = rest
                .split_once(':')
                .ok_or(FscryptKeySpecParseError::V1MissingKey)?;
            let descriptor = parse_descriptor(descriptor)?;
            let key = read_key(key)?;
            if key.len() < V1_KEY_BYTES {
                return Err(FscryptKeySpecParseError::V1KeyLength { found: key.len() });
            }
            return Ok(Self::v1(descriptor, key));
        }
        let key = spec.strip_prefix("v2:").unwrap_or(spec);
        Ok(Self::v2(read_key(key)?))
    }
}

/// Read the key half of a spec: raw bytes from a file for `@PATH`, hex
/// digits otherwise, checked against the length range fscrypt accepts.
fn read_key(text: &str) -> Result<Vec<u8>, FscryptKeySpecParseError> {
    let key = match text.strip_prefix('@') {
        Some(path) => std::fs::read(path).map_err(|source| FscryptKeySpecParseError::KeyFile {
            path: PathBuf::from(path),
            source,
        })?,
        None => parse_hex(text)?,
    };
    if key.len() < MIN_KEY_BYTES || key.len() > MAX_KEY_BYTES {
        return Err(FscryptKeySpecParseError::KeyLength { found: key.len() });
    }
    Ok(key)
}

/// Decode the 8-byte v1 descriptor.
fn parse_descriptor(text: &str) -> Result<[u8; DESCRIPTOR_BYTES], FscryptKeySpecParseError> {
    let bytes = parse_hex(text).map_err(|_| descriptor_error(text))?;
    <[u8; DESCRIPTOR_BYTES]>::try_from(bytes.as_slice()).map_err(|_| descriptor_error(text))
}

/// Report a bad descriptor, quoting it only while it is short enough to be
/// a mistyped descriptor rather than a key put in the wrong field.
fn descriptor_error(text: &str) -> FscryptKeySpecParseError {
    /// Above this many characters the field cannot be a plausible typo of
    /// 16 hex digits, and the shortest key fscrypt accepts is 32 of them.
    const QUOTABLE: usize = 20;

    FscryptKeySpecParseError::Descriptor {
        found: if text.len() <= QUOTABLE {
            format!("{text:?}")
        } else {
            format!("the {} characters supplied", text.len())
        },
    }
}

/// Decode a hex string, reporting *where* it stopped being hex rather than
/// quoting the string back — the string is usually a master key.
fn parse_hex(text: &str) -> Result<Vec<u8>, FscryptKeySpecParseError> {
    if !text.len().is_multiple_of(2) {
        return Err(FscryptKeySpecParseError::OddHex { digits: text.len() });
    }
    let digits: Vec<u8> = text.bytes().collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for (index, pair) in digits.as_chunks::<2>().0.iter().enumerate() {
        let high = hex_digit(pair[0]).ok_or(FscryptKeySpecParseError::NotHex {
            position: index * 2,
        })?;
        let low = hex_digit(pair[1]).ok_or(FscryptKeySpecParseError::NotHex {
            position: index * 2 + 1,
        })?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// Value of one ASCII hex digit.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 bytes of key material as hex, the length both versions accept.
    fn hex64() -> String {
        hex(&(0..64u8).collect::<Vec<_>>())
    }

    #[test]
    fn a_bare_hex_key_is_a_v2_key() {
        let spec: FscryptKeySpec = hex64().parse().expect("bare hex is a v2 key");
        assert_eq!(spec.version(), "v2");
        assert_eq!(spec.descriptor(), None);
        assert_eq!(spec.key(), (0..64u8).collect::<Vec<_>>());
    }

    #[test]
    fn the_v2_prefix_says_the_same_thing_explicitly() {
        let bare: FscryptKeySpec = hex64().parse().expect("bare");
        let prefixed: FscryptKeySpec = format!("v2:{}", hex64()).parse().expect("v2:");
        assert_eq!(bare, prefixed);
    }

    #[test]
    fn hex_is_read_in_either_case() {
        let lower: FscryptKeySpec = "aa".repeat(32).parse().expect("lowercase");
        let upper: FscryptKeySpec = "AA".repeat(32).parse().expect("uppercase");
        assert_eq!(lower, upper);
    }

    #[test]
    fn a_v1_key_carries_its_descriptor() {
        let spec: FscryptKeySpec = format!("v1:aabbccddeeff0011:{}", hex64())
            .parse()
            .expect("v1 spec");
        assert_eq!(spec.version(), "v1");
        assert_eq!(
            spec.descriptor(),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11])
        );
        assert_eq!(spec.key().len(), 64);
    }

    #[test]
    fn a_key_file_is_read_as_raw_bytes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ce.key");
        std::fs::write(&path, [0x5au8; 64]).expect("write the key file");
        let text = path.to_string_lossy().into_owned();

        let v2: FscryptKeySpec = format!("@{text}").parse().expect("@PATH is a v2 key");
        assert_eq!(v2.key(), [0x5a; 64]);
        let v2_explicit: FscryptKeySpec = format!("v2:@{text}").parse().expect("v2:@PATH");
        assert_eq!(v2, v2_explicit);

        let v1: FscryptKeySpec = format!("v1:0011223344556677:@{text}")
            .parse()
            .expect("v1 with @PATH");
        assert_eq!(v1.key(), [0x5a; 64]);
        assert_eq!(
            v1.descriptor(),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
        );
    }

    #[test]
    fn a_missing_key_file_names_the_path() {
        let error = "@no/such/key.bin"
            .parse::<FscryptKeySpec>()
            .expect_err("a key file that is not there");
        let message = error.to_string();
        assert!(
            message.contains("cannot read the fscrypt key from"),
            "{message}"
        );
        assert!(message.contains("key.bin"), "{message}");
    }

    #[test]
    fn a_short_or_long_key_is_rejected_by_length() {
        for text in ["aa".repeat(15), "aa".repeat(65)] {
            let error = text
                .parse::<FscryptKeySpec>()
                .expect_err("outside 16..=64 bytes");
            assert!(
                error.to_string().contains("key must be 16–64 bytes"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_v1_key_shorter_than_the_derivation_needs_is_rejected() {
        let error = format!("v1:aabbccddeeff0011:{}", "aa".repeat(32))
            .parse::<FscryptKeySpec>()
            .expect_err("32 bytes is too short for v1");
        assert!(
            error
                .to_string()
                .contains("v1 master keys must be at least 64 bytes"),
            "{error}"
        );
    }

    #[test]
    fn a_v1_descriptor_of_the_wrong_size_is_named_as_such() {
        for descriptor in ["aabb", "aabbccddeeff001122"] {
            let error = format!("v1:{descriptor}:{}", hex64())
                .parse::<FscryptKeySpec>()
                .expect_err("descriptor is not 8 bytes");
            let message = error.to_string();
            assert!(
                message.contains("v1 key descriptor must be 16 hex digits"),
                "{message}"
            );
            assert!(
                message.contains(descriptor),
                "a short field is quoted so the typo is visible: {message}"
            );
        }
    }

    #[test]
    fn a_key_typed_where_the_descriptor_goes_is_counted_rather_than_echoed() {
        // The one way key material could reach an error message: put the
        // key in the v1 descriptor's place and the descriptor after it.
        let error = format!("v1:{}:aabbccddeeff0011", hex64())
            .parse::<FscryptKeySpec>()
            .expect_err("128 hex digits is not a descriptor");
        let message = error.to_string();
        assert!(message.contains("the 128 characters supplied"), "{message}");
        assert!(!message.contains(&hex64()), "{message}");
    }

    #[test]
    fn a_v1_spec_without_a_key_says_how_it_is_spelled() {
        let error = "v1:aabbccddeeff0011"
            .parse::<FscryptKeySpec>()
            .expect_err("no key half");
        assert!(
            error.to_string().contains("v1:<DESCRIPTOR>:<KEY>"),
            "{error}"
        );
    }

    #[test]
    fn non_hex_is_reported_by_position_not_by_echoing_the_key() {
        let mut text = "aa".repeat(32);
        text.replace_range(10..11, "z");
        let error = text.parse::<FscryptKeySpec>().expect_err("z is not hex");
        let message = error.to_string();
        assert!(message.contains("position 10"), "{message}");
        assert!(!message.contains(&text), "the key text must not be echoed");
    }

    #[test]
    fn an_odd_number_of_hex_digits_is_rejected() {
        let error = "aaa"
            .parse::<FscryptKeySpec>()
            .expect_err("odd digit count");
        assert!(
            error.to_string().contains("even number of digits"),
            "{error}"
        );
    }

    #[test]
    fn debug_prints_lengths_and_descriptors_but_never_key_bytes() {
        let v1 = FscryptKeySpec::v1([0xab; 8], vec![0xcd; 64]);
        let rendered = format!("{v1:?}");
        assert!(rendered.contains("abababababababab"), "{rendered}");
        assert!(rendered.contains("key_bytes: 64"), "{rendered}");
        assert!(!rendered.contains("cd"), "{rendered}");

        let v2 = FscryptKeySpec::v2(vec![0xcd; 32]);
        let rendered = format!("{v2:?}");
        assert!(rendered.contains("key_bytes: 32"), "{rendered}");
        assert!(!rendered.contains("cd"), "{rendered}");
    }
}
