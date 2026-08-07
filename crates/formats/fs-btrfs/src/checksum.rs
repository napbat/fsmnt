//! Btrfs checksum algorithms shared by superblocks, tree blocks, and data.

use blake2::{Blake2b, Digest as _, digest::consts::U32};
use sha2::Sha256;

use crate::{BtrfsError, Result};

/// Checksum algorithm selected when the filesystem was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumType {
    /// CRC32C (Castagnoli), the historical default.
    Crc32c,
    /// xxHash64 with seed zero.
    XxHash64,
    /// SHA-256.
    Sha256,
    /// `BLAKE2b` with a 256-bit output.
    Blake2b256,
}

impl ChecksumType {
    pub(crate) fn from_raw(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Crc32c),
            1 => Ok(Self::XxHash64),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Blake2b256),
            other => Err(BtrfsError::UnsupportedChecksum { value: other }),
        }
    }

    #[cfg(feature = "fuzzing")]
    pub(crate) const fn raw(self) -> u16 {
        match self {
            Self::Crc32c => 0,
            Self::XxHash64 => 1,
            Self::Sha256 => 2,
            Self::Blake2b256 => 3,
        }
    }

    /// Number of meaningful bytes in an on-disk checksum field.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::Crc32c => 4,
            Self::XxHash64 => 8,
            Self::Sha256 | Self::Blake2b256 => 32,
        }
    }

    pub(crate) fn verify(self, expected: &[u8], data: &[u8]) -> bool {
        let actual = self.compute(data);
        expected
            .get(..self.size())
            .is_some_and(|stored| stored == &actual[..self.size()])
    }

    pub(crate) fn compute(self, data: &[u8]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        match self {
            Self::Crc32c => {
                output[..4].copy_from_slice(&crc32c::crc32c(data).to_le_bytes());
            }
            Self::XxHash64 => {
                output[..8].copy_from_slice(&xxhash_rust::xxh64::xxh64(data, 0).to_le_bytes());
            }
            Self::Sha256 => {
                output.copy_from_slice(&Sha256::digest(data));
            }
            Self::Blake2b256 => {
                output.copy_from_slice(&<Blake2b<U32>>::digest(data));
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::ChecksumType;

    #[test]
    fn checksum_algorithms_match_known_vectors() {
        assert_eq!(
            &ChecksumType::Crc32c.compute(b"123456789")[..4],
            &[0x83, 0x92, 0x06, 0xe3]
        );
        assert_eq!(
            &ChecksumType::XxHash64.compute(b"")[..8],
            &[0x99, 0xe9, 0xd8, 0x51, 0x37, 0xdb, 0x46, 0xef]
        );
        assert_eq!(
            ChecksumType::Sha256.compute(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            ChecksumType::Blake2b256.compute(b"abc"),
            [
                0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
                0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
                0x68, 0xd5, 0x23, 0x19,
            ]
        );
    }

    #[test]
    fn verification_uses_only_the_selected_checksum_width() {
        for algorithm in [
            ChecksumType::Crc32c,
            ChecksumType::XxHash64,
            ChecksumType::Sha256,
            ChecksumType::Blake2b256,
        ] {
            let mut expected = algorithm.compute(b"payload");
            expected[algorithm.size()..].fill(0xff);
            assert!(algorithm.verify(&expected, b"payload"));
            expected[0] ^= 1;
            assert!(!algorithm.verify(&expected, b"payload"));
        }
    }
}
