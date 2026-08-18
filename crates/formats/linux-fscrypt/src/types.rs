//! Public fscrypt types — keys, descriptors, policy summary.
//!
//! Distinguished from the on-disk `FscryptContext` (in `policy.rs`) so
//! the public API doesn't change when the on-disk format does.

use crate::error::{FscryptError, Result};

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Kernel `FSCRYPT_MIN_KEY_SIZE`.
pub const FSCRYPT_MIN_KEY_SIZE: usize = 16;
/// Kernel `FSCRYPT_MAX_KEY_SIZE`.
pub const FSCRYPT_MAX_KEY_SIZE: usize = 64;

/// fscrypt master key (16..=64 bytes per kernel range).
///
/// Buffer is fixed-length so the type stays `Copy`-cheap for callers
/// that need to clone keys, and zeroize-on-drop is straightforward.
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FscryptMasterKey {
    bytes: [u8; FSCRYPT_MAX_KEY_SIZE],
    len: u8,
}

impl FscryptMasterKey {
    /// Construct from a slice of length 16..=64.
    ///
    /// # Errors
    ///
    /// Returns [`FscryptError::InvalidPolicy`] when `bytes` is shorter
    /// than 16 bytes or longer than 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FSCRYPT_MIN_KEY_SIZE || bytes.len() > FSCRYPT_MAX_KEY_SIZE {
            return Err(FscryptError::InvalidPolicy {
                inode: 0,
                reason: "fscrypt master key length outside [16, 64] range",
            });
        }
        let mut buf = [0u8; FSCRYPT_MAX_KEY_SIZE];
        buf[..bytes.len()].copy_from_slice(bytes);
        let len = u8::try_from(bytes.len()).map_err(|_| FscryptError::InvalidPolicy {
            inode: 0,
            reason: "fscrypt master key length does not fit its encoded field",
        })?;
        Ok(Self { bytes: buf, len })
    }

    /// Construct from a fixed 64-byte array (the modal case).
    #[must_use]
    pub fn from_array(bytes: [u8; FSCRYPT_MAX_KEY_SIZE]) -> Self {
        Self { bytes, len: 64 }
    }

    /// Borrow the active prefix of the buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl PartialEq for FscryptMasterKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl core::fmt::Debug for FscryptMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FscryptMasterKey(<redacted, {} bytes>)", self.len)
    }
}

/// 8-byte v1 master key descriptor (`fscrypt_context_v1.master_key_descriptor`).
///
/// `PartialEq` is the standard byte comparison so the type can be used as a
/// `BTreeMap` / `HashMap` key without violating the `k1 == k2 → hash(k1) ==
/// hash(k2)` contract. Use [`FscryptKeyDescriptor::ct_eq`] when a side-channel-
/// free comparison is needed (descriptors aren't secret per se, but they
/// shouldn't leak through timing during keystore lookup either).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FscryptKeyDescriptor(pub [u8; 8]);

impl Ord for FscryptKeyDescriptor {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for FscryptKeyDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ConstantTimeEq for FscryptKeyDescriptor {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// 16-byte v2 master key identifier (`fscrypt_context_v2.master_key_identifier`).
///
/// See [`FscryptKeyDescriptor`] for the rationale on `PartialEq` vs `ct_eq`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FscryptKeyIdentifier(pub [u8; 16]);

impl Ord for FscryptKeyIdentifier {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for FscryptKeyIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ConstantTimeEq for FscryptKeyIdentifier {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Which fscrypt policy version applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FscryptPolicyKind {
    /// Version 1 policy using an eight-byte master-key descriptor.
    V1,
    /// Version 2 policy using a sixteen-byte master-key identifier.
    V2,
}

/// Public summary of a parsed fscrypt policy.
///
/// Carries everything callers need to identify the master key required
/// to decrypt this object, plus the raw mode bytes for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FscryptPolicy {
    /// Version and key-reference scheme used by the policy.
    pub kind: FscryptPolicyKind,
    /// On-disk algorithm identifier used for file contents.
    pub contents_mode: u8,
    /// On-disk algorithm identifier used for filenames and symlinks.
    pub filenames_mode: u8,
    /// Raw fscrypt policy flags controlling IV and padding behavior.
    pub flags: u8,
    /// 0 means "fs block size"; non-zero values are unsupported.
    pub log2_data_unit_size: u8,
    /// Some for v1, None for v2.
    pub key_descriptor: Option<FscryptKeyDescriptor>,
    /// Some for v2, None for v1.
    pub key_identifier: Option<FscryptKeyIdentifier>,
    /// Per-file nonce used when deriving this inode's encryption keys.
    pub nonce: [u8; 16],
}

impl FscryptPolicy {
    /// Padding bytes per `flags & 0x03`.
    #[must_use]
    pub fn padding_bytes(&self) -> usize {
        4usize << (self.flags & 0x03)
    }
}

// fscrypt content/filenames mode identifiers (one-byte values on the
// wire, per `include/uapi/linux/fscrypt.h`). Modes 2 and 3 were
// AES-256-GCM and AES-256-CBC in the pre-4.0 drafts and were never
// shipped; the kernel leaves the numbers reserved.

/// `FSCRYPT_MODE_AES_256_XTS` — AES-256-XTS file contents.
pub const FSCRYPT_MODE_AES_256_XTS: u8 = 1;
/// `FSCRYPT_MODE_AES_256_CTS` — AES-256-CBC-CTS filenames.
pub const FSCRYPT_MODE_AES_256_CTS: u8 = 4;
/// `FSCRYPT_MODE_AES_128_CBC` — AES-128-CBC-ESSIV file contents.
pub const FSCRYPT_MODE_AES_128_CBC: u8 = 5;
/// `FSCRYPT_MODE_AES_128_CTS` — AES-128-CBC-CTS filenames.
pub const FSCRYPT_MODE_AES_128_CTS: u8 = 6;
/// `FSCRYPT_MODE_SM4_XTS` — SM4-XTS file contents.
pub const FSCRYPT_MODE_SM4_XTS: u8 = 7;
/// `FSCRYPT_MODE_SM4_CTS` — SM4-CBC-CTS filenames.
pub const FSCRYPT_MODE_SM4_CTS: u8 = 8;
/// `FSCRYPT_MODE_ADIANTUM` — Adiantum contents *and* filenames.
pub const FSCRYPT_MODE_ADIANTUM: u8 = 9;
/// `FSCRYPT_MODE_AES_256_HCTR2` — AES-256-HCTR2 filenames.
pub const FSCRYPT_MODE_AES_256_HCTR2: u8 = 10;

/// Strategy used to derive the per-block content IV (AES-XTS tweak /
/// Adiantum tweak). Selected by `policy.flags` at cipher-construction
/// time so `decrypt_block` only has to look up a value, not branch on
/// policy state on every block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IvDerivation {
    /// Default: IV is the logical block index, used directly as the
    /// XTS tweak / Adiantum tweak low bytes (low 64 bits stored little-
    /// endian for both ciphers).
    PerFileBlockIndex,
    /// `IV_INO_LBLK_64`: low 8 bytes = LE u64 of
    /// `(lblk_num & 0xFFFFFFFF) | (inode_number << 32)`.
    InoLblk64 {
        /// Inode the IV is anchored to.
        inode_number: u32,
    },
    /// `IV_INO_LBLK_32`: low 8 bytes = LE u64 of
    /// `((lblk_num & 0xFFFFFFFF) + hashed_ino) & 0xFFFFFFFF`,
    /// where `hashed_ino = (siphash24(inode_le8, INODE_HASH_KEY)) as u32`.
    /// The siphash key is per-FS so the hash is precomputed at cipher
    /// construction.
    InoLblk32 {
        /// Low 32 bits of `siphash24(le8(inode), INODE_HASH_KEY)`.
        hashed_ino: u32,
    },
    /// `DIRECT_KEY` (v2 + Adiantum only): IV is `lblk_le8 || ci_nonce_16
    /// || zero_remainder` per kernel `fscrypt_generate_iv`:
    ///   `memcpy(iv->nonce, ci->ci_nonce, FSCRYPT_FILE_NONCE_SIZE);`
    ///   `iv->index = cpu_to_le64(lblk_num);`
    /// The mode key is the per-mode HKDF derivation (`HKDF_CONTEXT_DIRECT_KEY`,
    /// info = `[mode_num]`, no FS UUID); the per-file nonce only enters
    /// through the IV here.
    DirectKey {
        /// The object's per-file nonce, written into IV bytes 8..24.
        nonce: [u8; 16],
    },
}

impl IvDerivation {
    /// Compute the full 32-byte IV / tweak for the per-block crypto
    /// operation, mirroring kernel `fscrypt_generate_iv`. Wide-block
    /// ciphers (Adiantum, HCTR2) consume all 32 bytes; AES-XTS uses
    /// only the low 16.
    ///
    /// Kernel order is: `memset(iv, 0, ivsize)` → `DIRECT_KEY`'s
    /// `memcpy(iv->nonce, ci->ci_nonce, 16)` at offset 8..24 → final
    /// `iv->index = cpu_to_le64(index)` at offset 0..8. The index write
    /// happens last so it does not overlap the nonce.
    #[must_use]
    pub fn full_iv(self, lblk_num: u64) -> [u8; 32] {
        let mut iv = [0u8; 32];
        // DIRECT_KEY: write ci_nonce at offset 8..24 (matches kernel
        // `union fscrypt_iv::nonce` offset). For Adiantum, ivsize=32 so
        // bytes 24..32 remain zero from the initial memset.
        if let Self::DirectKey { nonce } = self {
            iv[8..24].copy_from_slice(&nonce);
        }
        let value = match self {
            // Backward-compatible default: existing callers passed the
            // logical block index directly. Preserve that by returning
            // the lblk_num as the LE u64 low half.
            //
            // DIRECT_KEY shares this branch — kernel only modifies the
            // nonce field; the index is still `cpu_to_le64(lblk_num)`.
            Self::PerFileBlockIndex | Self::DirectKey { .. } => lblk_num,
            Self::InoLblk64 { inode_number } => {
                // Kernel `fscrypt_generate_iv` masks lblk_num to its low
                // 32 bits via `WARN_ON_ONCE((u32)lblk != lblk)` then
                // proceeds; mirror by decoding the low four bytes.
                let bytes = lblk_num.to_le_bytes();
                let lblk32 =
                    u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                let ino64 = u64::from(inode_number);
                lblk32 | (ino64 << 32)
            }
            Self::InoLblk32 { hashed_ino } => {
                let bytes = lblk_num.to_le_bytes();
                let lblk32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                u64::from(lblk32.wrapping_add(hashed_ino))
            }
        };
        iv[..8].copy_from_slice(&value.to_le_bytes());
        iv
    }

    /// Compute the AES-XTS tweak — the low 16 bytes of [`Self::full_iv`].
    /// Provided as a convenience for callers wired to AES-XTS specifically;
    /// wide-block callers should use `full_iv` directly.
    #[must_use]
    pub fn xts_tweak(self, lblk_num: u64) -> [u8; 16] {
        let mut tweak = [0u8; 16];
        tweak.copy_from_slice(&self.full_iv(lblk_num)[..16]);
        tweak
    }
}

/// Per-file key length required by `mode`.
///
/// Returns `None` for modes that are not yet supported; callers map
/// `None` to [`FscryptError::UnsupportedMode`] at the call site,
/// where the full `(contents, filenames, flags)` policy diagnostic is
/// available. A single-mode helper cannot construct that diagnostic
/// alone, which is why this returns `Option` rather than `Result`.
#[must_use]
pub fn mode_keysize(mode: u8) -> Option<usize> {
    match mode {
        FSCRYPT_MODE_AES_256_XTS => Some(64),
        FSCRYPT_MODE_AES_256_CTS
        | FSCRYPT_MODE_ADIANTUM
        | FSCRYPT_MODE_AES_256_HCTR2
        | FSCRYPT_MODE_SM4_XTS => Some(32),
        FSCRYPT_MODE_AES_128_CBC | FSCRYPT_MODE_AES_128_CTS | FSCRYPT_MODE_SM4_CTS => Some(16),
        // Per kernel `fscrypt_modes`:
        //   FSCRYPT_MODE_SM4_XTS keysize = 32 (k1 || k2, two SM4-128 keys)
        //   FSCRYPT_MODE_SM4_CTS keysize = 16 (single SM4-128 key)
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_from_bytes_min_size_16_ok() {
        let k = FscryptMasterKey::from_bytes(&[0u8; 16]).unwrap();
        assert_eq!(k.as_bytes().len(), 16);
    }

    #[test]
    fn master_key_from_bytes_max_size_64_ok() {
        let k = FscryptMasterKey::from_bytes(&[0u8; 64]).unwrap();
        assert_eq!(k.as_bytes().len(), 64);
    }

    #[test]
    fn master_key_from_bytes_too_short_rejects() {
        let err = FscryptMasterKey::from_bytes(&[0u8; 15]).unwrap_err();
        assert!(matches!(
            err,
            crate::error::FscryptError::InvalidPolicy { .. }
        ));
    }

    #[test]
    fn master_key_from_bytes_too_long_rejects() {
        let err = FscryptMasterKey::from_bytes(&[0u8; 65]).unwrap_err();
        assert!(matches!(
            err,
            crate::error::FscryptError::InvalidPolicy { .. }
        ));
    }

    #[test]
    fn master_key_from_array_round_trips() {
        let k = FscryptMasterKey::from_array([0xAB; 64]);
        assert_eq!(k.as_bytes(), &[0xAB; 64]);
    }

    #[test]
    fn descriptor_eq_constant_time() {
        let a = FscryptKeyDescriptor([1u8; 8]);
        let b = FscryptKeyDescriptor([1u8; 8]);
        let c = FscryptKeyDescriptor([2u8; 8]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn identifier_eq_constant_time() {
        let a = FscryptKeyIdentifier([1u8; 16]);
        let b = FscryptKeyIdentifier([1u8; 16]);
        let c = FscryptKeyIdentifier([2u8; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn mode_keysize_known_modes() {
        assert_eq!(mode_keysize(FSCRYPT_MODE_AES_256_XTS), Some(64));
        assert_eq!(mode_keysize(FSCRYPT_MODE_AES_256_CTS), Some(32));
        assert_eq!(mode_keysize(FSCRYPT_MODE_ADIANTUM), Some(32));
    }

    #[test]
    fn mode_keysize_unknown_returns_none() {
        // Modes 2, 3 are reserved-or-unsupported. (5/6 are AES-128,
        // 7/8 are SM4, 9 is Adiantum, 10 is HCTR2 — covered by their
        // own tests.)
        assert_eq!(mode_keysize(2), None);
        assert_eq!(mode_keysize(3), None);
        assert_eq!(mode_keysize(11), None);
        assert_eq!(mode_keysize(0xFF), None);
    }

    #[test]
    fn mode_keysize_aes_128_modes() {
        assert_eq!(mode_keysize(FSCRYPT_MODE_AES_128_CBC), Some(16));
        assert_eq!(mode_keysize(FSCRYPT_MODE_AES_128_CTS), Some(16));
    }

    #[test]
    fn mode_keysize_sm4_modes() {
        // Kernel `fscrypt_modes`:
        //   FSCRYPT_MODE_SM4_XTS keysize = 32 (XTS uses two SM4-128 keys)
        //   FSCRYPT_MODE_SM4_CTS keysize = 16
        assert_eq!(mode_keysize(FSCRYPT_MODE_SM4_XTS), Some(32));
        assert_eq!(mode_keysize(FSCRYPT_MODE_SM4_CTS), Some(16));
    }

    #[test]
    fn mode_keysize_aes_256_hctr2() {
        // Kernel `fscrypt_modes[FSCRYPT_MODE_AES_256_HCTR2].keysize = 32`.
        assert_eq!(mode_keysize(FSCRYPT_MODE_AES_256_HCTR2), Some(32));
    }

    #[test]
    fn xts_tweak_per_file_block_index_is_lblk_le() {
        let tweak = IvDerivation::PerFileBlockIndex.xts_tweak(7);
        assert_eq!(&tweak[..8], &7u64.to_le_bytes());
        assert!(tweak[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn xts_tweak_iv_ino_lblk_64_matches_kernel_reference() {
        // Kernel: iv_value = (lblk & 0xFFFFFFFF) | (ino << 32).
        // For ino=12, lblk=3: iv = 0x0000000C_00000003.
        let tweak = IvDerivation::InoLblk64 { inode_number: 12 }.xts_tweak(3);
        let expected = [
            0x03, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(tweak, expected);
    }

    #[test]
    fn xts_tweak_iv_ino_lblk_64_masks_high_bits_of_lblk() {
        // Kernel `WARN_ON_ONCE((u32)lblk != lblk)` then proceeds with
        // the low 32 bits. Verify the >32-bit input is truncated.
        let tweak = IvDerivation::InoLblk64 { inode_number: 0xAA }.xts_tweak(0x1_0000_0007);
        let expected = [
            0x07, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(tweak, expected);
    }

    #[test]
    fn xts_tweak_iv_ino_lblk_32_matches_kernel_reference() {
        // Kernel: iv_value = ((lblk & 0xFFFFFFFF) + hashed_ino) & 0xFFFFFFFF.
        // For lblk=3, hashed_ino=0x378f3ff6: iv = 0x378f3ff9.
        let tweak = IvDerivation::InoLblk32 {
            hashed_ino: 0x378f_3ff6,
        }
        .xts_tweak(3);
        let expected = [0xf9, 0x3f, 0x8f, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(tweak, expected);
    }

    #[test]
    fn full_iv_per_file_block_index_zeroes_high_bytes() {
        // Default policy: lblk_le8 in bytes 0..8, bytes 8..32 all zero
        // (kernel `memset(iv, 0, ivsize)`).
        let iv = IvDerivation::PerFileBlockIndex.full_iv(42);
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(iv, expected);
    }

    #[test]
    fn full_iv_direct_key_layout_matches_kernel() {
        // Kernel `fscrypt_generate_iv` under DIRECT_KEY:
        //   memset(iv, 0, ivsize=32);
        //   memcpy(iv->nonce, ci->ci_nonce, 16);   // bytes 8..24
        //   iv->index = cpu_to_le64(index);        // bytes 0..8
        // Bytes 24..32 remain zero.
        let nonce: [u8; 16] = core::array::from_fn(|i| ((i).to_le_bytes()[0]) ^ 0x5A);
        let iv = IvDerivation::DirectKey { nonce }.full_iv(7);
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&7u64.to_le_bytes());
        expected[8..24].copy_from_slice(&nonce);
        assert_eq!(iv, expected);
    }

    #[test]
    fn full_iv_iv_ino_lblk_64_zero_high_bytes() {
        let iv = IvDerivation::InoLblk64 { inode_number: 12 }.full_iv(3);
        let mut expected = [0u8; 32];
        let value = 3u64 | (12u64 << 32);
        expected[..8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(iv, expected);
    }

    #[test]
    fn xts_tweak_is_low_16_bytes_of_full_iv() {
        // Sanity: the convenience wrapper agrees with full_iv()[..16]
        // for every variant. Pins the refactor against silent drift.
        for iv_derivation in [
            IvDerivation::PerFileBlockIndex,
            IvDerivation::InoLblk64 { inode_number: 99 },
            IvDerivation::InoLblk32 {
                hashed_ino: 0xDEAD_BEEF,
            },
            IvDerivation::DirectKey { nonce: [0xCD; 16] },
        ] {
            let lblk = 17u64;
            assert_eq!(
                iv_derivation.xts_tweak(lblk),
                iv_derivation.full_iv(lblk)[..16]
            );
        }
    }

    #[test]
    fn xts_tweak_iv_ino_lblk_32_wraps_u32() {
        // hashed_ino = 0xFFFFFFFF, lblk = 5 → wrap to 4.
        let tweak = IvDerivation::InoLblk32 {
            hashed_ino: 0xFFFF_FFFF,
        }
        .xts_tweak(5);
        let expected = [0x04, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(tweak, expected);
    }
}
