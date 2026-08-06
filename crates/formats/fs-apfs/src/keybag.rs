//! Keybag parsing and protection-class metadata.
//!
//! APFS encryption metadata is held in keybags: the container keybag lists
//! per-volume key blobs, and each volume keybag lists wrapped volume keys and
//! passphrase hints. This module parses the (decrypted) keybag structure —
//! decrypting the keybag itself is the key-hierarchy work.
//!
//! Apple File System Reference, `14-encryption.md`.

use alloc::vec::Vec;

use crate::error::{ApfsError, Result};
use crate::object::OBJ_PHYS_SIZE;

/// Size of the fixed `kb_locker_t` header (before `kl_entries`).
pub const KB_LOCKER_HEADER_SIZE: usize = 16;
/// Size of the fixed `keybag_entry_t` header (before `ke_keydata`).
pub const KEYBAG_ENTRY_HEADER_SIZE: usize = 24;
/// The only supported keybag layout version (`APFS_KEYBAG_VERSION`).
///
/// Version one used an incompatible, undocumented prototype layout.
pub const APFS_KEYBAG_VERSION: u16 = 2;
/// Upper bound on a keybag entry's key data (`APFS_VOL_KEYBAG_ENTRY_MAX_SIZE`).
pub const APFS_VOL_KEYBAG_ENTRY_MAX_SIZE: usize = 512;
/// Mask selecting the effective protection class (`CP_EFFECTIVE_CLASSMASK`).
pub const CP_EFFECTIVE_CLASSMASK: u32 = 0x0000_001F;
/// The crypto-id value used by software-encrypted volumes (`CRYPTO_SW_ID`).
pub const CRYPTO_SW_ID: u64 = 4;
/// UUID identifying a `FileVault` personal recovery key entry.
pub const APFS_FV_PERSONAL_RECOVERY_KEY_UUID: &str = "EBC6C064-0000-11AA-AA11-00306543ECAC";

/// A keybag-entry tag (`KB_TAG_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeybagTag {
    /// Unknown tag.
    Unknown,
    /// A wrapped volume encryption key.
    VolumeKey,
    /// Volume unlock records (keys wrapped by a user passphrase).
    VolumeUnlockRecords,
    /// A passphrase hint.
    VolumePassphraseHint,
    /// A wrapping media key.
    WrappingMKey,
    /// A volume media key.
    VolumeMKey,
    /// A tag value this parser does not recognize.
    Other(u16),
}

impl KeybagTag {
    /// Decodes a `ke_tag` value.
    #[must_use]
    pub fn from_value(value: u16) -> Self {
        match value {
            0 => Self::Unknown,
            2 => Self::VolumeKey,
            3 => Self::VolumeUnlockRecords,
            4 => Self::VolumePassphraseHint,
            5 => Self::WrappingMKey,
            6 => Self::VolumeMKey,
            other => Self::Other(other),
        }
    }
}

/// An APFS data-protection class (`cp_key_class_t`, `PROTECTION_CLASS_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionClass {
    /// No class; a directory's default is used (`PROTECTION_CLASS_DIR_NONE`).
    DirNone,
    /// Class A — complete protection.
    A,
    /// Class B — protected unless open.
    B,
    /// Class C — protected until first user authentication.
    C,
    /// Class D — no protection.
    D,
    /// Class F — no protection, non-persistent key.
    F,
    /// Class M.
    M,
    /// A class value this parser does not recognize.
    Unknown(u32),
}

impl ProtectionClass {
    /// Decodes a protection class from a `cp_key_class_t`, masking off the
    /// non-class bits.
    #[must_use]
    pub fn from_value(value: u32) -> Self {
        match value & CP_EFFECTIVE_CLASSMASK {
            0 => Self::DirNone,
            1 => Self::A,
            2 => Self::B,
            3 => Self::C,
            4 => Self::D,
            6 => Self::F,
            14 => Self::M,
            other => Self::Unknown(other),
        }
    }
}

/// One entry of a keybag (`keybag_entry_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeybagEntry {
    /// The entry's UUID — a volume UUID, or a recovery-key UUID.
    pub uuid: [u8; 16],
    /// The entry's tag.
    pub tag: KeybagTag,
    /// The entry's key data (a wrapped key, a hint string, …).
    pub key_data: Vec<u8>,
}

/// A parsed (decrypted) keybag (`kb_locker_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keybag {
    /// The keybag format version.
    pub version: u16,
    /// The keybag's entries.
    pub entries: Vec<KeybagEntry>,
}

impl Keybag {
    /// Parses a keybag from its decrypted bytes.
    ///
    /// Accepts either a bare `kb_locker_t` or a whole `media_keybag_t` block
    /// (whose `obj_phys_t` header is skipped).
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] or [`ApfsError::Malformed`] when an
    /// entry runs past the keybag.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // A media_keybag_t prefixes the kb_locker with an obj_phys_t header;
        // detect it by checking whether a leading object header is present.
        let locker = if bytes.len() >= OBJ_PHYS_SIZE + KB_LOCKER_HEADER_SIZE
            && looks_like_locker(&bytes[OBJ_PHYS_SIZE..])
        {
            &bytes[OBJ_PHYS_SIZE..]
        } else {
            bytes
        };
        if locker.len() < KB_LOCKER_HEADER_SIZE {
            return Err(ApfsError::Truncated {
                structure: "kb_locker_t",
                expected: KB_LOCKER_HEADER_SIZE,
                actual: locker.len(),
            });
        }
        let version = u16::from_le_bytes([locker[0], locker[1]]);
        // Version one is an incompatible prototype layout; decoding it as v2
        // would yield silently corrupted entries.
        if version != APFS_KEYBAG_VERSION {
            return Err(ApfsError::Unsupported("unsupported keybag layout version"));
        }
        let nkeys = usize::from(u16::from_le_bytes([locker[2], locker[3]]));

        let mut entries = Vec::with_capacity(nkeys);
        let mut cursor = KB_LOCKER_HEADER_SIZE;
        for _ in 0..nkeys {
            let header = locker
                .get(cursor..cursor + KEYBAG_ENTRY_HEADER_SIZE)
                .ok_or(ApfsError::Malformed {
                    structure: "keybag_entry_t",
                    reason: "entry header extends past the keybag",
                })?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&header[0..16]);
            let tag = KeybagTag::from_value(u16::from_le_bytes([header[16], header[17]]));
            let keylen = usize::from(u16::from_le_bytes([header[18], header[19]]));
            // APFS bounds a keybag entry's key data; a larger value is
            // structural corruption, not a longer-than-usual key.
            if keylen >= APFS_VOL_KEYBAG_ENTRY_MAX_SIZE {
                return Err(ApfsError::Malformed {
                    structure: "keybag_entry_t",
                    reason: "key data length exceeds the APFS maximum",
                });
            }

            let data_start = cursor + KEYBAG_ENTRY_HEADER_SIZE;
            let key_data = locker
                .get(data_start..data_start + keylen)
                .ok_or(ApfsError::Malformed {
                    structure: "keybag_entry_t",
                    reason: "entry key data extends past the keybag",
                })?
                .to_vec();
            entries.push(KeybagEntry {
                uuid,
                tag,
                key_data,
            });

            // Entries are stored aligned to sixteen-byte boundaries.
            let entry_len = KEYBAG_ENTRY_HEADER_SIZE + keylen;
            cursor += entry_len.wrapping_add(15) & !15;
        }
        Ok(Self { version, entries })
    }

    /// Returns the first entry with the given tag, if any.
    #[must_use]
    pub fn entry_with_tag(&self, tag: KeybagTag) -> Option<&KeybagEntry> {
        self.entries.iter().find(|entry| entry.tag == tag)
    }

    /// The volume passphrase hint, decoded as UTF-8, if the keybag has one.
    #[must_use]
    pub fn passphrase_hint(&self) -> Option<alloc::string::String> {
        let entry = self.entry_with_tag(KeybagTag::VolumePassphraseHint)?;
        let end = entry
            .key_data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(entry.key_data.len());
        Some(alloc::string::String::from_utf8_lossy(&entry.key_data[..end]).into_owned())
    }
}

/// Heuristic: whether `bytes` plausibly begins with a `kb_locker_t` rather
/// than being raw keybag data — used to skip a `media_keybag_t` header.
fn looks_like_locker(bytes: &[u8]) -> bool {
    if bytes.len() < KB_LOCKER_HEADER_SIZE {
        return false;
    }
    // kl_nbytes should not exceed the available data; the padding is zero.
    let nbytes = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    nbytes <= bytes.len() && bytes[8..16].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `kb_locker_t` from `(uuid, tag, key_data)` entries.
    fn keybag(version: u16, entries: &[([u8; 16], u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&version.to_le_bytes());
        b.extend_from_slice(
            &u16::try_from(entries.len())
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        b.extend_from_slice(&0u32.to_le_bytes()); // kl_nbytes (filled below)
        b.extend_from_slice(&[0u8; 8]); // padding
        for (uuid, tag, data) in entries {
            let start = b.len();
            b.extend_from_slice(uuid);
            b.extend_from_slice(&tag.to_le_bytes());
            b.extend_from_slice(
                &u16::try_from(data.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b.extend_from_slice(&[0u8; 4]); // padding
            b.extend_from_slice(data);
            // Pad the entry to a sixteen-byte boundary.
            let aligned = ((b.len() - start) + 15) & !15;
            b.resize(start + aligned, 0);
        }
        let nbytes = u32::try_from(b.len()).expect("the test fixture value fits in u32");
        b[4..8].copy_from_slice(&nbytes.to_le_bytes());
        b
    }

    #[test]
    fn keybag_tag_decodes() {
        assert_eq!(KeybagTag::from_value(2), KeybagTag::VolumeKey);
        assert_eq!(KeybagTag::from_value(4), KeybagTag::VolumePassphraseHint);
        assert_eq!(KeybagTag::from_value(99), KeybagTag::Other(99));
    }

    #[test]
    fn protection_class_decodes_and_masks() {
        assert_eq!(ProtectionClass::from_value(0), ProtectionClass::DirNone);
        assert_eq!(ProtectionClass::from_value(1), ProtectionClass::A);
        assert_eq!(ProtectionClass::from_value(4), ProtectionClass::D);
        // High bits outside CP_EFFECTIVE_CLASSMASK are ignored.
        assert_eq!(ProtectionClass::from_value(0xFF00 | 3), ProtectionClass::C);
    }

    #[test]
    fn parses_a_keybag_with_two_entries() {
        let bag = keybag(
            2,
            &[
                ([0x11; 16], 2, vec![0xAA; 32]),        // VolumeKey
                ([0x22; 16], 4, b"my hint\0".to_vec()), // PassphraseHint
            ],
        );
        let kb = Keybag::parse(&bag).unwrap();
        assert_eq!(kb.version, 2);
        assert_eq!(kb.entries.len(), 2);
        assert_eq!(kb.entries[0].tag, KeybagTag::VolumeKey);
        assert_eq!(kb.entries[0].key_data, vec![0xAA; 32]);
        assert_eq!(kb.passphrase_hint().as_deref(), Some("my hint"));
    }

    #[test]
    fn entry_lookup_by_tag() {
        let bag = keybag(2, &[([0x33; 16], 6, vec![1, 2, 3])]);
        let kb = Keybag::parse(&bag).unwrap();
        assert!(kb.entry_with_tag(KeybagTag::VolumeMKey).is_some());
        assert!(kb.entry_with_tag(KeybagTag::VolumeKey).is_none());
    }

    #[test]
    fn rejects_an_unsupported_keybag_version() {
        let bag = keybag(1, &[]);
        assert!(matches!(
            Keybag::parse(&bag),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_an_oversized_key_entry_length() {
        let mut bag = keybag(2, &[([0x44; 16], 2, vec![1, 2, 3])]);
        // ke_keylen sits at offset +18 of the first entry, which begins at
        // KB_LOCKER_HEADER_SIZE.
        let keylen_off = KB_LOCKER_HEADER_SIZE + 18;
        bag[keylen_off..keylen_off + 2].copy_from_slice(
            &u16::try_from(APFS_VOL_KEYBAG_ENTRY_MAX_SIZE)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        assert!(matches!(
            Keybag::parse(&bag),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn entry_past_the_keybag_is_rejected() {
        let mut bag = keybag(2, &[]);
        // Claim one entry but provide no entry bytes.
        bag[2..4].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            Keybag::parse(&bag),
            Err(ApfsError::Malformed { .. })
        ));
    }

    /// Prefixes `bag` with an `obj_phys_t` header whose first byte differs from
    /// the `kb_locker` version's low byte. The wrapper turns a bare keybag into
    /// the `media_keybag_t` form that requires header detection to skip.
    fn media_keybag(bag: Vec<u8>) -> Vec<u8> {
        let mut wrapped = vec![0u8; OBJ_PHYS_SIZE];
        // A non-zero checksum byte ensures the obj_phys prefix is NOT a valid
        // kb_locker (whose version field starts with 0x02).
        wrapped[0] = 0xAB;
        wrapped.extend(bag);
        wrapped
    }

    #[test]
    fn parses_a_media_keybag_with_an_obj_phys_prefix() {
        // A `media_keybag_t` carries an `obj_phys_t` header before its
        // kb_locker. `Keybag::parse` must detect the wrapper and skip it.
        //
        // Killed mutants:
        //   * `looks_like_locker -> false` — the wrapper would never be
        //     detected and parse would read garbage from the obj_phys bytes.
        //   * `<` → `==`/`>`/`<=` in `looks_like_locker`'s length check.
        //   * `<=` → `>` in the `nbytes <= bytes.len()` heuristic.
        let bare = keybag(2, &[([0x55; 16], 2, vec![0xCD; 8])]);
        let wrapped = media_keybag(bare);
        let kb = Keybag::parse(&wrapped).unwrap();
        assert_eq!(kb.version, 2);
        assert_eq!(kb.entries.len(), 1);
        assert_eq!(kb.entries[0].tag, KeybagTag::VolumeKey);
        assert_eq!(kb.entries[0].key_data, vec![0xCD; 8]);
    }

    #[test]
    fn parses_a_media_keybag_header_only() {
        // A minimal media_keybag — obj_phys (32) + kb_locker header (16) — is
        // exactly 48 bytes. The header-detection gate is `bytes.len() >=
        // OBJ_PHYS_SIZE + KB_LOCKER_HEADER_SIZE`; mutating `+` to `*` would
        // require 512 bytes and parse the obj_phys prefix as the kb_locker
        // (version byte 0xAB != 2), surfacing an Unsupported error.
        let bare = keybag(2, &[]);
        let wrapped = media_keybag(bare);
        assert_eq!(wrapped.len(), OBJ_PHYS_SIZE + KB_LOCKER_HEADER_SIZE);
        let kb = Keybag::parse(&wrapped).unwrap();
        assert_eq!(kb.version, 2);
        assert!(kb.entries.is_empty());
    }
}
