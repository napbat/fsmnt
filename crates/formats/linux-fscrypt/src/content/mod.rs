//! Content decryption for fscrypt-encrypted file blocks.
//!
//! Dispatches on `policy.contents_mode`:
//!  - `FSCRYPT_MODE_AES_256_XTS` (1) → AES-256-XTS with u128 LE block
//!    index as tweak.
//!  - `FSCRYPT_MODE_AES_128_CBC` (5) → AES-128-CBC with `essiv(cbc(aes))`
//!    per-block IV (kernel `crypto/essiv.c`): per-block CBC IV =
//!    AES-256-ECB(SHA-256(content_key))(plain_iv).
//!  - `FSCRYPT_MODE_ADIANTUM` (9)   → Adiantum with 32-byte tweak
//!    `lblk_u64.to_le_bytes() || [0u8; 24]`.
//!
//! Hole blocks (zero-filled by the underlying mapper) are NOT
//! decrypted — kernel zero-fills holes before the crypto pass.

use alloc::boxed::Box;

use aes::Aes256;
#[cfg(test)]
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
#[cfg(test)]
use aes::cipher::generic_array::GenericArray;
#[cfg(test)]
use sha2::{Digest, Sha256};
use sm4::Sm4;
use xts_mode::Xts128;
use zeroize::Zeroizing;

use crate::adiantum::{ADIANTUM_KEY_SIZE, ADIANTUM_TWEAK_SIZE, AdiantumCipher};
use crate::error::{FscryptError, Result};
use crate::keyderive::derive_file_key;
use crate::keystore::FscryptKeystore;
use crate::params::FsParams;
use crate::types::{
    FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_256_XTS,
    FSCRYPT_MODE_SM4_XTS, FscryptPolicy, IvDerivation, mode_keysize,
};

mod essiv;

use essiv::Aes128CbcEssivCipher;

/// Content cipher for one fscrypt-encrypted file, dispatching by mode.
pub struct ContentCipher {
    inner: ContentCipherInner,
    iv: IvDerivation,
    /// Bytes per fscrypt data unit. Equals the fs block size for
    /// default policies; for v2 policies with `log2_data_unit_size != 0`
    /// it is `1 << log2_data_unit_size` and `decrypt_block` walks each
    /// fs-block in `data_unit_size` chunks with a per-unit IV.
    data_unit_size: usize,
}

enum ContentCipherInner {
    AesXts(Box<Xts128<Aes256>>),
    Sm4Xts(Box<Xts128<Sm4>>),
    Aes128CbcEssiv(Box<Aes128CbcEssivCipher>),
    Adiantum(Box<AdiantumCipher>),
}

impl ContentCipher {
    /// Build a content cipher with an explicit IV-derivation strategy
    /// and data-unit size.
    ///
    /// The IV strategy is selected by `policy.flags`; the policy / key /
    /// strategy must agree (e.g. `InoLblk64` requires the policy's
    /// `IV_INO_LBLK_64` flag and the per-mode-per-FS key, not the
    /// per-file key).
    ///
    /// `data_unit_size` is the bytes-per-data-unit chosen by the
    /// caller: fs block size for default policies, `1 <<
    /// policy.log2_data_unit_size` for sub-block policies. Callers must
    /// pass blocks whose length is a multiple of `data_unit_size`.
    ///
    /// # Errors
    ///
    /// Returns [`FscryptError::UnsupportedMode`] when `contents_mode`
    /// names a cipher this crate does not implement, and
    /// [`FscryptError::InvalidPolicy`] when `key` is the wrong length
    /// for the mode.
    ///
    /// # Panics
    ///
    /// The per-mode key installs cannot fail once the length check
    /// above has passed, so their `expect`s are unreachable.
    pub fn with_iv(
        policy: &FscryptPolicy,
        key: &[u8],
        iv: IvDerivation,
        data_unit_size: usize,
    ) -> Result<Self> {
        let want = mode_keysize(policy.contents_mode).ok_or(FscryptError::UnsupportedMode {
            inode: 0,
            contents: policy.contents_mode,
            filenames: policy.filenames_mode,
            flags: policy.flags,
        })?;
        if key.len() != want {
            return Err(FscryptError::InvalidPolicy {
                inode: 0,
                reason: "content key length does not match mode",
            });
        }

        match policy.contents_mode {
            FSCRYPT_MODE_AES_256_XTS => {
                let cipher_1 =
                    Aes256::new_from_slice(&key[..32]).expect("first half is a valid AES-256 key");
                let cipher_2 =
                    Aes256::new_from_slice(&key[32..]).expect("second half is a valid AES-256 key");
                Ok(Self {
                    inner: ContentCipherInner::AesXts(Box::new(Xts128::<Aes256>::new(
                        cipher_1, cipher_2,
                    ))),
                    iv,
                    data_unit_size,
                })
            }
            FSCRYPT_MODE_SM4_XTS => {
                // SM4-XTS uses two SM4-128 keys (k1 || k2). Same XTS
                // tweak shape as AES-256-XTS — only the inner block
                // cipher swaps; `xts-mode::Xts128` is generic over the
                // underlying `BlockEncrypt + BlockDecrypt + BlockCipher`
                // type with a 16-byte block, which SM4 satisfies.
                let cipher_1 =
                    Sm4::new_from_slice(&key[..16]).expect("first half is a valid SM4 key");
                let cipher_2 =
                    Sm4::new_from_slice(&key[16..]).expect("second half is a valid SM4 key");
                Ok(Self {
                    inner: ContentCipherInner::Sm4Xts(Box::new(Xts128::<Sm4>::new(
                        cipher_1, cipher_2,
                    ))),
                    iv,
                    data_unit_size,
                })
            }
            FSCRYPT_MODE_AES_128_CBC => {
                // validate_supported pairs AES-128-CBC only with AES-128-CTS
                // and only without DIRECT_KEY (DIRECT_KEY requires Adiantum).
                // The IvDerivation reaching here is therefore PerFileBlockIndex
                // (default) — IV_INO_LBLK_* is rejected by validate_supported.
                let mut k = Zeroizing::new([0u8; 16]);
                k.copy_from_slice(key);
                Ok(Self {
                    inner: ContentCipherInner::Aes128CbcEssiv(Box::new(Aes128CbcEssivCipher::new(
                        &k,
                    ))),
                    iv,
                    data_unit_size,
                })
            }
            FSCRYPT_MODE_ADIANTUM => {
                let mut k = Zeroizing::new([0u8; ADIANTUM_KEY_SIZE]);
                k.copy_from_slice(key);
                Ok(Self {
                    inner: ContentCipherInner::Adiantum(Box::new(AdiantumCipher::new(&k))),
                    iv,
                    data_unit_size,
                })
            }
            other => Err(FscryptError::UnsupportedMode {
                inode: 0,
                contents: other,
                filenames: policy.filenames_mode,
                flags: policy.flags,
            }),
        }
    }

    /// Decrypt one filesystem block in place using the given logical
    /// block index. The IV / tweak follows the strategy selected at
    /// construction time (`PerFileBlockIndex` for default v1/v2 policies,
    /// `InoLblk64` / `InoLblk32` for inline-crypto modes).
    ///
    /// For default `data_unit_size = fs_block_size`, the whole block
    /// decrypts under a single tweak with `lblk = block_index`. For
    /// sub-block policies, the block is walked in `data_unit_size`-byte
    /// chunks with absolute unit index
    /// `block_index * (block.len() / data_unit_size) + i` driving each
    /// chunk's tweak.
    ///
    /// # Errors
    ///
    /// Returns [`FscryptError::InvalidPolicy`] when `block.len()` is not
    /// a multiple of the data-unit size, when AES-128-CBC-ESSIV is
    /// handed a data-unit size that is not a multiple of the AES block,
    /// or when the absolute data-unit index would overflow.
    ///
    /// # Panics
    ///
    /// Panics if the absolute data-unit index exceeds `u64::MAX` — which
    /// needs a file larger than 2^64 data units, beyond any filesystem
    /// fscrypt runs on.
    pub fn decrypt_block(&self, block: &mut [u8], block_index: u128) -> Result<()> {
        if !block.len().is_multiple_of(self.data_unit_size) {
            return Err(FscryptError::InvalidPolicy {
                inode: 0,
                reason: "encrypted block length is not a multiple of the data unit size",
            });
        }
        let units_per_block = block.len() / self.data_unit_size;
        let first_unit_index = block_index.checked_mul(units_per_block as u128).ok_or(
            FscryptError::InvalidPolicy {
                inode: 0,
                reason: "data-unit index overflows u128",
            },
        )?;

        match &self.inner {
            ContentCipherInner::AesXts(xts) => {
                // `xts-mode::decrypt_area` walks `block` in
                // `data_unit_size`-byte chunks, calling `get_tweak_fn`
                // with `first_unit_index + i` per chunk — exactly the
                // absolute unit index we want feeding the IV.
                xts.decrypt_area(
                    block,
                    self.data_unit_size,
                    first_unit_index,
                    |unit_idx: u128| {
                        let abs_unit = u64::try_from(unit_idx)
                            .expect("absolute unit index fits in u64 for any real-world file");
                        self.iv.xts_tweak(abs_unit)
                    },
                );
                Ok(())
            }
            ContentCipherInner::Sm4Xts(xts) => {
                // Mirrors the AES-XTS path verbatim — `xts-mode` walks
                // `block` in `data_unit_size`-byte chunks calling the
                // tweak callback with `first_unit_index + i` per chunk,
                // i.e. the absolute unit index. SM4-XTS uses the same
                // little-endian-u64 tweak as AES-256-XTS.
                xts.decrypt_area(
                    block,
                    self.data_unit_size,
                    first_unit_index,
                    |unit_idx: u128| {
                        let abs_unit = u64::try_from(unit_idx)
                            .expect("absolute unit index fits in u64 for any real-world file");
                        self.iv.xts_tweak(abs_unit)
                    },
                );
                Ok(())
            }
            ContentCipherInner::Aes128CbcEssiv(cipher) => {
                if !self.data_unit_size.is_multiple_of(16) {
                    return Err(FscryptError::InvalidPolicy {
                        inode: 0,
                        reason: "AES-128-CBC-ESSIV data unit size must be a multiple of 16",
                    });
                }
                for i in 0..units_per_block {
                    let abs_unit = first_unit_index
                        .checked_add(i as u128)
                        .expect("unit index in-range for any real-world file");
                    let abs_unit =
                        u64::try_from(abs_unit).expect("absolute unit index fits in u64");
                    // ESSIV plain_iv = kernel `union fscrypt_iv` low 16 bytes
                    // (`fscrypt_generate_iv` writes lblk_le8 at offset 0;
                    // bytes 8..16 stay zero for AES-128-CBC because
                    // validate_supported rejects DIRECT_KEY here, so the
                    // nonce-bearing IV variant cannot reach this arm).
                    let plain_iv = self.iv.xts_tweak(abs_unit);
                    let start = i * self.data_unit_size;
                    cipher.decrypt_unit(&mut block[start..start + self.data_unit_size], plain_iv);
                }
                Ok(())
            }
            ContentCipherInner::Adiantum(cipher) => {
                for i in 0..units_per_block {
                    let abs_unit = first_unit_index
                        .checked_add(i as u128)
                        .expect("unit index in-range for any real-world file");
                    let abs_unit =
                        u64::try_from(abs_unit).expect("absolute unit index fits in u64");
                    // Adiantum's 32-byte tweak == kernel `union fscrypt_iv`
                    // raw view: bytes 0..8 = lblk_le8, bytes 8..24 = ci_nonce
                    // (only under DIRECT_KEY; otherwise zero), bytes 24..32
                    // always zero.
                    let adi_tweak: [u8; ADIANTUM_TWEAK_SIZE] = self.iv.full_iv(abs_unit);
                    let start = i * self.data_unit_size;
                    cipher.decrypt_in_place(
                        &adi_tweak,
                        &mut block[start..start + self.data_unit_size],
                    )?;
                }
                Ok(())
            }
        }
    }
}

/// Bytes per fscrypt data unit under `policy` on a filesystem with
/// `block_size`-byte blocks.
///
/// `log2_data_unit_size == 0` means "one data unit per fs block", the
/// only shape available before kernel 6.7 and still the common one.
/// [`validate_supported`](crate::policy::validate_supported) has already
/// bounded any non-zero value to `[SECTOR_SHIFT, log2(block_size)]`, so
/// the shift below cannot overflow and the result always divides the
/// block size.
#[must_use]
pub fn data_unit_size(policy: &FscryptPolicy, block_size: u32) -> usize {
    if policy.log2_data_unit_size == 0 {
        block_size as usize
    } else {
        1usize << policy.log2_data_unit_size
    }
}

/// Build a [`ContentCipher`] from a policy the host has already read off
/// disk, plus the registered master keys.
///
///   - Default v1/v2 policies: per-file key via the v1 or v2 KDF (the
///     per-file nonce as input), IV = logical block index.
///   - v2 + `IV_INO_LBLK_64` / `IV_INO_LBLK_32`: per-mode-per-FS key via
///     the v2 KDF (`mode_num` + FS UUID), IV derived from inode + lblk.
///   - v2 + `DIRECT_KEY`: per-mode key with no FS UUID, per-file nonce
///     carried in the IV instead.
///
/// # Errors
///
/// Returns [`FscryptError::UnsupportedMode`] for a policy outside the
/// supported matrix, [`FscryptError::MissingKey`] when no master key is
/// registered for it, [`FscryptError::KeyUnwrapFailed`] when a
/// hardware-wrapped key will not unwrap, and
/// [`FscryptError::InvalidPolicy`] when the derived key length does not
/// match the mode.
pub fn build_content_cipher(
    keys: &FscryptKeystore,
    policy: &FscryptPolicy,
    inode_number: u32,
    params: &FsParams,
) -> Result<ContentCipher> {
    crate::policy::validate_supported(
        policy,
        inode_number,
        params.block_size_log2(),
        params.has_stable_inodes,
    )?;
    let (key, iv) = derive_file_key(keys, policy, inode_number, params, policy.contents_mode)?;
    ContentCipher::with_iv(policy, &key, iv, data_unit_size(policy, params.block_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FscryptKeyIdentifier, FscryptPolicyKind};

    #[test]
    fn content_cipher_adiantum_dispatch_invokes_decrypt() {
        // Pin the dispatch wiring: ContentCipher with contents_mode =
        // FSCRYPT_MODE_ADIANTUM routes to AdiantumCipher and actually
        // runs the cipher. A no-op early return in the Adiantum arm
        // would leave the input zero-filled; Adiantum has full
        // avalanche, so decrypting a zero block under a non-trivial
        // key produces non-zero output.
        //
        // Key is from `adiantum_decrypt_kat_short` (kernel testmgr.h [0]).
        // End-to-end byte-level correctness is covered by Task 19's
        // integration test against the real ext4 fixture; the dispatch
        // test only proves the cipher is invoked.
        use crate::adiantum::ADIANTUM_KEY_SIZE;

        #[rustfmt::skip]
        const KEY: [u8; ADIANTUM_KEY_SIZE] = [
            0x9e, 0xeb, 0xb2, 0x49, 0x3c, 0x1c, 0xf5, 0xf4,
            0x6a, 0x99, 0xc2, 0xc4, 0xdf, 0xb1, 0xf4, 0xdd,
            0x75, 0x20, 0x57, 0xea, 0x2c, 0x4f, 0xcd, 0xb2,
            0xa5, 0x3d, 0x7b, 0x49, 0x1e, 0xab, 0xfd, 0x0f,
        ];

        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_ADIANTUM,
            filenames_mode: FSCRYPT_MODE_ADIANTUM,
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };

        let cipher = ContentCipher::with_iv(&policy, &KEY, IvDerivation::PerFileBlockIndex, 4096)
            .expect("Adiantum ContentCipher constructs");

        let mut block = [0u8; 4096];
        cipher
            .decrypt_block(&mut block, 0)
            .expect("Adiantum decrypt_block returns Ok");
        assert!(
            block.iter().any(|&b| b != 0),
            "Adiantum decrypt of zero block must produce non-zero output"
        );
    }

    /// `DIRECT_KEY` plumbing: a non-zero per-file nonce in
    /// `IvDerivation::DirectKey` must reach the Adiantum tweak (bytes
    /// 8..24 of the 32-byte IV). Decrypting the same zero block under
    /// the same key with `DirectKey { nonce }` vs. `PerFileBlockIndex`
    /// would yield identical output if the nonce never made it through.
    #[test]
    fn direct_key_adiantum_nonce_changes_iv() {
        use crate::adiantum::ADIANTUM_KEY_SIZE;
        let key = [0xA5u8; ADIANTUM_KEY_SIZE];
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_ADIANTUM,
            filenames_mode: FSCRYPT_MODE_ADIANTUM,
            flags: 0x02 | 0x04,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let nonce: [u8; 16] = core::array::from_fn(|i| ((i).to_le_bytes()[0]) ^ 0x33);

        let cipher_direct =
            ContentCipher::with_iv(&policy, &key, IvDerivation::DirectKey { nonce }, 4096)
                .expect("DirectKey ContentCipher constructs");
        let cipher_default =
            ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 4096)
                .expect("default ContentCipher constructs");

        let mut block_a = [0u8; 4096];
        let mut block_b = [0u8; 4096];
        cipher_direct.decrypt_block(&mut block_a, 0).unwrap();
        cipher_default.decrypt_block(&mut block_b, 0).unwrap();
        assert_ne!(
            block_a, block_b,
            "DirectKey nonce must change the Adiantum tweak"
        );
    }

    /// `DIRECT_KEY` with the all-zero nonce must agree byte-for-byte with
    /// the default `PerFileBlockIndex` IV: kernel `fscrypt_generate_iv`
    /// only writes the nonce into bytes 8..24, so a zero nonce leaves
    /// the IV identical to the default-policy IV.
    #[test]
    fn direct_key_adiantum_zero_nonce_matches_default_iv() {
        use crate::adiantum::ADIANTUM_KEY_SIZE;
        let key = [0x42u8; ADIANTUM_KEY_SIZE];
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_ADIANTUM,
            filenames_mode: FSCRYPT_MODE_ADIANTUM,
            flags: 0x02 | 0x04,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let cipher_direct = ContentCipher::with_iv(
            &policy,
            &key,
            IvDerivation::DirectKey { nonce: [0u8; 16] },
            4096,
        )
        .expect("DirectKey ContentCipher constructs");
        let cipher_default =
            ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 4096)
                .expect("default ContentCipher constructs");

        let mut block_a = [0u8; 4096];
        let mut block_b = [0u8; 4096];
        cipher_direct.decrypt_block(&mut block_a, 5).unwrap();
        cipher_default.decrypt_block(&mut block_b, 5).unwrap();
        assert_eq!(
            block_a, block_b,
            "zero nonce must produce the same IV as PerFileBlockIndex"
        );
    }

    /// AES-128-CBC-ESSIV round-trip: encrypt a known plaintext under
    /// the kernel's exact ESSIV construction (`essiv_iv` =
    /// AES-256-ECB(SHA-256(content_key))(plain_iv); CBC-encrypt the
    /// data unit with `content_key` + `essiv_iv`), then decrypt via
    /// `ContentCipher` and assert byte-for-byte equality. A
    /// single-IV-skip-ESSIV bug or AES-128-ECB-vs-AES-256-ECB salt
    /// confusion would break this test.
    #[test]
    fn aes_128_cbc_essiv_round_trips_against_kernel_iv() {
        use crate::types::FSCRYPT_MODE_AES_128_CBC;
        use aes::Aes128;

        let content_key = {
            let mut k = [0u8; 16];
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((i).to_le_bytes()[0]) ^ 0x77;
            }
            k
        };
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_128_CBC,
            filenames_mode: 6, // FSCRYPT_MODE_AES_128_CTS
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };

        let cipher =
            ContentCipher::with_iv(&policy, &content_key, IvDerivation::PerFileBlockIndex, 4096)
                .expect("AES-128-CBC-ESSIV cipher constructs");

        let block_index: u128 = 5;
        let mut block = [0u8; 4096];
        for (i, b) in block.iter_mut().enumerate() {
            *b = ((i).to_le_bytes()[0]).wrapping_mul(11);
        }
        let original = block;

        // Build the reference ciphertext using the same construction the
        // kernel applies under the hood:
        //   plain_iv     = lblk_le8 || zero[8]
        //   essiv_iv     = AES-256-ECB(SHA-256(content_key))(plain_iv)
        //   block_ct     = AES-128-CBC(content_key, essiv_iv)(block_pt)
        let mut plain_iv = [0u8; 16];
        plain_iv[..8].copy_from_slice(
            &(u64::try_from(block_index).expect("the test fixture value fits in u64"))
                .to_le_bytes(),
        );
        let salt = Sha256::digest(content_key);
        let essiv_inner = Aes256::new_from_slice(&salt).unwrap();
        let mut essiv_iv = plain_iv;
        essiv_inner.encrypt_block(GenericArray::from_mut_slice(&mut essiv_iv));

        let aes128 = Aes128::new_from_slice(&content_key).unwrap();
        let mut prev = essiv_iv;
        for chunk in block.chunks_exact_mut(16) {
            for i in 0..16 {
                chunk[i] ^= prev[i];
            }
            aes128.encrypt_block(GenericArray::from_mut_slice(chunk));
            prev.copy_from_slice(chunk);
        }
        assert_ne!(block, original);

        cipher
            .decrypt_block(&mut block, block_index)
            .expect("AES-128-CBC-ESSIV decrypt_block returns Ok");
        assert_eq!(block, original);
    }

    /// AES-128-CBC-ESSIV `with_iv` rejects a wrong-size key. The mode
    /// guarantees a 16-byte key; passing 32 must surface as
    /// `InvalidFscryptPolicy` (not panic).
    #[test]
    fn aes_128_cbc_essiv_rejects_wrong_key_size() {
        use crate::types::FSCRYPT_MODE_AES_128_CBC;
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_128_CBC,
            filenames_mode: 6,
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let result =
            ContentCipher::with_iv(&policy, &[0u8; 32], IvDerivation::PerFileBlockIndex, 4096);
        assert!(matches!(
            result.err(),
            Some(FscryptError::InvalidPolicy { .. })
        ));
    }

    /// SM4-XTS round-trip: encrypt a known plaintext under the kernel's
    /// XTS construction (two SM4-128 keys, `lblk_le8` || zero[8] tweak),
    /// then decrypt with `ContentCipher` and verify byte-for-byte.
    /// Pins the dispatch wiring + agreement with `xts-mode::Xts128<Sm4>`.
    #[test]
    fn sm4_xts_round_trips_against_kernel_iv() {
        use crate::types::FSCRYPT_MODE_SM4_XTS;
        use sm4::Sm4;

        let key = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((i).to_le_bytes()[0]).wrapping_add(0x37);
            }
            k
        };
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_SM4_XTS,
            filenames_mode: 8, // FSCRYPT_MODE_SM4_CTS
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let cipher =
            ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 4096).unwrap();

        let mut block = [0xC9u8; 4096];
        let original = block;

        // Reference encrypt under the same Xts128<Sm4> construction.
        let cipher_1 = Sm4::new_from_slice(&key[..16]).unwrap();
        let cipher_2 = Sm4::new_from_slice(&key[16..]).unwrap();
        let xts_enc = Xts128::<Sm4>::new(cipher_1, cipher_2);
        let tweak: [u8; 16] = 5u128.to_le_bytes();
        xts_enc.encrypt_area(&mut block, 4096, 0, |_| tweak);
        assert_ne!(block, original);

        cipher.decrypt_block(&mut block, 5).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn round_trips_with_xts_encrypt() {
        // Build the same Xts128 used by the kernel to encrypt a block,
        // then decrypt with our wrapper and compare against the original.
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i).to_le_bytes()[0];
        }
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let cipher =
            ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 4096).unwrap();

        let mut block = [0xABu8; 4096];
        let original = block;

        let cipher_1 = Aes256::new_from_slice(&key[..32]).unwrap();
        let cipher_2 = Aes256::new_from_slice(&key[32..]).unwrap();
        let xts_enc = Xts128::<Aes256>::new(cipher_1, cipher_2);
        let tweak: [u8; 16] = 7u128.to_le_bytes();
        xts_enc.encrypt_area(&mut block, 4096, 0, |_| tweak);
        assert_ne!(block, original);

        cipher.decrypt_block(&mut block, 7).unwrap();
        assert_eq!(block, original);
    }

    /// `IV_INO_LBLK_64` round-trip: encrypt a known plaintext with AES-XTS
    /// using the kernel-aligned tweak `lblk32 | (ino << 32)`, then decrypt
    /// with `ContentCipher::with_iv(InoLblk64 { inode_number })` and verify
    /// the plaintext comes back. This pins the dispatch wiring end-to-end.
    #[test]
    fn iv_ino_lblk_64_round_trip_against_kernel_iv() {
        let key = {
            let mut k = [0u8; 64];
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((i).to_le_bytes()[0]).wrapping_add(1);
            }
            k
        };
        let inode_number = 12u32;
        let lblk = 3u128;
        let expected_iv_value = (u64::try_from(lblk).expect("the test fixture value fits in u64")
            & 0xFFFF_FFFF)
            | (u64::from(inode_number) << 32);

        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0x02 | 0x08, // PAD_16 | IV_INO_LBLK_64
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };

        let cipher = ContentCipher::with_iv(
            &policy,
            &key,
            IvDerivation::InoLblk64 { inode_number },
            4096,
        )
        .expect("InoLblk64 cipher constructs");

        let mut block = [0xC3u8; 4096];
        let original = block;

        // Encrypt with the same AES-XTS primitive and the expected IV.
        let cipher_1 = Aes256::new_from_slice(&key[..32]).unwrap();
        let cipher_2 = Aes256::new_from_slice(&key[32..]).unwrap();
        let xts_enc = Xts128::<Aes256>::new(cipher_1, cipher_2);
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&expected_iv_value.to_le_bytes());
        xts_enc.encrypt_area(&mut block, 4096, 0, |_| tweak);
        assert_ne!(block, original);

        cipher
            .decrypt_block(&mut block, lblk)
            .expect("InoLblk64 decrypt_block returns Ok");
        assert_eq!(block, original);
    }

    /// `IV_INO_LBLK_32` round-trip: same as above with the
    /// `(lblk + hashed_ino) as u32` IV.
    #[test]
    fn iv_ino_lblk_32_round_trip_against_kernel_iv() {
        let key = {
            let mut k = [0u8; 64];
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((i).to_le_bytes()[0]).wrapping_sub(7);
            }
            k
        };
        let hashed_ino = 0xDEAD_BEEFu32;
        let lblk = 5u128;
        let expected_iv_value = u64::from(
            (u32::try_from(lblk).expect("the test fixture value fits in u32"))
                .wrapping_add(hashed_ino),
        );

        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0x02 | 0x10, // PAD_16 | IV_INO_LBLK_32
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };

        let cipher =
            ContentCipher::with_iv(&policy, &key, IvDerivation::InoLblk32 { hashed_ino }, 4096)
                .expect("InoLblk32 cipher constructs");

        let mut block = [0x99u8; 4096];
        let original = block;

        let cipher_1 = Aes256::new_from_slice(&key[..32]).unwrap();
        let cipher_2 = Aes256::new_from_slice(&key[32..]).unwrap();
        let xts_enc = Xts128::<Aes256>::new(cipher_1, cipher_2);
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&expected_iv_value.to_le_bytes());
        xts_enc.encrypt_area(&mut block, 4096, 0, |_| tweak);
        assert_ne!(block, original);

        cipher
            .decrypt_block(&mut block, lblk)
            .expect("InoLblk32 decrypt_block returns Ok");
        assert_eq!(block, original);
    }

    #[test]
    fn inode_hash_low32_matches_kernel_reference() {
        // Cross-check against the Python-computed value:
        // SipHash-2-4(ino_hash_key, le8(12)) & 0xFFFFFFFF == 0x378f3ff6.
        // Key derived via HKDF over the all-zero master key with
        // INODE_HASH_KEY context = 0x55b798d9b8c776f44ceca06c150f4d12.
        let ino_hash_key: [u8; 16] = [
            0x55, 0xb7, 0x98, 0xd9, 0xb8, 0xc7, 0x76, 0xf4, 0x4c, 0xec, 0xa0, 0x6c, 0x15, 0x0f,
            0x4d, 0x12,
        ];
        let got = crate::dirhash::inode_hash_low32(&ino_hash_key, 12);
        assert_eq!(got, 0x378f_3ff6);
    }

    #[test]
    fn new_rejects_wrong_key_size() {
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        // AES-256-XTS requires 64 bytes; passing 32 should fail.
        let result =
            ContentCipher::with_iv(&policy, &[0u8; 32], IvDerivation::PerFileBlockIndex, 4096);
        assert!(matches!(
            result.err(),
            Some(FscryptError::InvalidPolicy { .. })
        ));
    }

    /// Sub-block AES-XTS round-trip with `data_unit_size = 512` on a
    /// 4 KiB fs-block: encrypt eight 512-byte sectors with the kernel's
    /// per-sector tweak (absolute unit index = `block_index` * 8 + i),
    /// then decrypt with `ContentCipher` and assert the plaintext comes
    /// back. A single-IV-per-block implementation would only round-trip
    /// the first unit, so the per-byte equality check catches that
    /// regression.
    #[test]
    fn xts_dus_512_round_trip_against_kernel_iv() {
        let key = {
            let mut k = [0u8; 64];
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((i).to_le_bytes()[0]).wrapping_mul(3);
            }
            k
        };
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0x02,
            log2_data_unit_size: 9,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };

        let data_unit_size = 512usize;
        let block_size = 4096usize;
        let units_per_block = block_size / data_unit_size;
        let block_index: u128 = 2;

        let mut block = [0u8; 4096];
        for (i, b) in block.iter_mut().enumerate() {
            *b = ((i).to_le_bytes()[0]) ^ 0xA5;
        }
        let original = block;

        // Encrypt each 512-byte sector with the kernel's per-unit tweak.
        let cipher_1 = Aes256::new_from_slice(&key[..32]).unwrap();
        let cipher_2 = Aes256::new_from_slice(&key[32..]).unwrap();
        let xts_enc = Xts128::<Aes256>::new(cipher_1, cipher_2);
        for i in 0..units_per_block {
            let abs_unit = (u64::try_from(block_index)
                .expect("the test fixture value fits in u64"))
                * (units_per_block as u64)
                + i as u64;
            let mut tweak = [0u8; 16];
            tweak[..8].copy_from_slice(&abs_unit.to_le_bytes());
            let start = i * data_unit_size;
            xts_enc.encrypt_area(
                &mut block[start..start + data_unit_size],
                data_unit_size,
                0,
                |_| tweak,
            );
        }
        assert_ne!(block, original);

        let cipher = ContentCipher::with_iv(
            &policy,
            &key,
            IvDerivation::PerFileBlockIndex,
            data_unit_size,
        )
        .expect("XTS DUS=512 cipher constructs");
        cipher
            .decrypt_block(&mut block, block_index)
            .expect("DUS=512 decrypt_block returns Ok");
        assert_eq!(block, original);
    }

    /// `decrypt_block` must fail-closed when the block length is not a
    /// multiple of `data_unit_size`. Reading a partial block from the
    /// fs layer would indicate an upstream bug; the cipher must not
    /// silently decrypt a partial chunk.
    #[test]
    fn dus_misaligned_block_rejected() {
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: 4,
            flags: 0x02,
            log2_data_unit_size: 9,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let key = [0u8; 64];
        let cipher = ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 512)
            .expect("DUS=512 cipher constructs");
        // 4097 % 512 != 0; must reject before touching the cipher.
        let mut block = vec![0u8; 4097];
        let err = cipher.decrypt_block(&mut block, 0).unwrap_err();
        assert!(matches!(err, FscryptError::InvalidPolicy { .. }));
    }
}
