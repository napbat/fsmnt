//! Encrypted directory-entry name decoding.
//!
//! Filenames are encrypted with AES-256-CBC-CTS (CS3), key derived from
//! the v1 or v2 KDF using the `PER_FILE_ENC_KEY` context. The plaintext
//! is padded with NUL bytes up to a multiple of `padding_amount = 4 <<
//! (flags & 0x03)` (with a minimum of 16 bytes); after decrypting, the
//! trailing NUL pad is stripped.

#![cfg(feature = "fscrypt")]

use zeroize::Zeroizing;

use aes::{Aes128, Aes256};
use sm4::Sm4;

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::fscrypt::adiantum::{ADIANTUM_TWEAK_SIZE, AdiantumCipher};
use crate::fscrypt::hctr2::{HCTR2_TWEAK_SIZE, Hctr2Cipher};
use crate::fscrypt::types::{
    FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_128_CTS, FSCRYPT_MODE_AES_256_CTS,
    FSCRYPT_MODE_AES_256_HCTR2, FSCRYPT_MODE_SM4_CTS, FscryptPolicy, FscryptPolicyKind,
    IvDerivation, mode_keysize,
};
use crate::fscrypt::{cts, kdf_v1, kdf_v2, policy};

/// Decrypt a single AES-256-CTS dirent ciphertext name with the given
/// filenames key, then strip trailing NUL padding. Test-only helper for
/// the legacy 32-byte path; production callers use [`FilenameCipher`].
#[cfg(test)]
fn decrypt_name(filenames_key: &[u8; 32], ciphertext: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    let mut pt = cts::decrypt_cs3::<Aes256>(filenames_key, &[0u8; 16], ciphertext)?;
    while let Some(&0) = pt.last() {
        pt.pop();
    }
    Ok(pt)
}

/// Typed cipher for fscrypt filename / symlink-target decryption.
///
/// Wraps the 32-byte filenames key together with cipher dispatch and an
/// IV-derivation strategy. Default policies use `PerFileBlockIndex` which
/// resolves to a zero IV at `lblk=0` (matching the kernel's
/// `fscrypt_generate_iv(0, ci)` for filenames). `IV_INO_LBLK_*` policies
/// produce a non-zero IV derived from the parent inode number, mirroring
/// the kernel's `lblk_num |= ino << 32` / `lblk_num += hashed_ino`.
///
/// `decrypt_name` / `decrypt_name_into` honour a single padding contract:
/// callers receive plaintext with trailing NUL padding already stripped.
pub(crate) struct FilenameCipher {
    inner: FilenameCipherInner,
    iv: IvDerivation,
}

enum FilenameCipherInner {
    AesCts256(Zeroizing<[u8; 32]>),
    AesCts128(Zeroizing<[u8; 16]>),
    Sm4Cts(Zeroizing<[u8; 16]>),
    // Boxed to avoid a large_enum_variant warning: AdiantumCipher is ~1168 bytes.
    Adiantum(alloc::boxed::Box<AdiantumCipher>),
    Hctr2(alloc::boxed::Box<Hctr2Cipher>),
}

impl FilenameCipher {
    /// Build the cipher from a parsed policy, the derived filenames key
    /// (length determined by `mode_keysize(policy.filenames_mode)`), and
    /// an explicit IV-derivation strategy.
    ///
    /// `key` length must equal the per-mode key size: 32 for
    /// AES-256-CTS / Adiantum, 16 for AES-128-CTS. Mismatches surface as
    /// `InvalidFscryptPolicy` rather than panicking.
    pub(crate) fn new(policy: &FscryptPolicy, key: &[u8], iv: IvDerivation) -> Result<Self> {
        let want = mode_keysize(policy.filenames_mode).ok_or(ExtError::UnsupportedFscryptMode {
            inode: 0,
            contents: policy.contents_mode,
            filenames: policy.filenames_mode,
            flags: policy.flags,
        })?;
        if key.len() != want {
            return Err(ExtError::InvalidFscryptPolicy {
                inode: 0,
                reason: "filename key length does not match mode",
            });
        }

        let inner = match policy.filenames_mode {
            FSCRYPT_MODE_AES_256_CTS => {
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(key);
                FilenameCipherInner::AesCts256(k)
            }
            FSCRYPT_MODE_AES_128_CTS => {
                let mut k = Zeroizing::new([0u8; 16]);
                k.copy_from_slice(key);
                FilenameCipherInner::AesCts128(k)
            }
            FSCRYPT_MODE_SM4_CTS => {
                // SM4-CBC-CTS: same CS3 wrapper as AES-256-CTS, just with
                // a 16-byte SM4 key. `cts::decrypt_cs3` is generic over the
                // inner block cipher; SM4 plugs in via `Sm4` from the
                // RustCrypto `sm4` crate.
                let mut k = Zeroizing::new([0u8; 16]);
                k.copy_from_slice(key);
                FilenameCipherInner::Sm4Cts(k)
            }
            FSCRYPT_MODE_ADIANTUM => {
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(key);
                FilenameCipherInner::Adiantum(alloc::boxed::Box::new(AdiantumCipher::new(&k)))
            }
            FSCRYPT_MODE_AES_256_HCTR2 => {
                // Kernel `fscrypt_valid_enc_modes_v2` (lines 84-86) only
                // accepts HCTR2 as the **filenames** mode, paired with
                // AES-256-XTS contents. The 32-byte key derived via the
                // standard per-file KDF is the AES-256 key for the inner
                // block cipher / XCTR keystream.
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(key);
                FilenameCipherInner::Hctr2(alloc::boxed::Box::new(Hctr2Cipher::new(&k)))
            }
            other => {
                return Err(ExtError::UnsupportedFscryptMode {
                    inode: 0,
                    contents: policy.contents_mode,
                    filenames: other,
                    flags: policy.flags,
                });
            }
        };
        Ok(Self { inner, iv })
    }

    /// Decrypt a filename or symlink-target ciphertext and strip trailing
    /// NUL padding into `out`. Reuses `out` as scratch.
    ///
    /// **Padding contract:** callers receive padding-stripped plaintext.
    /// Do NOT strip again at the call site.
    pub(crate) fn decrypt_name_into(
        &self,
        on_disk: &[u8],
        out: &mut alloc::vec::Vec<u8>,
    ) -> Result<()> {
        out.clear();
        // Kernel `fscrypt_fname_encrypt` calls `fscrypt_generate_iv(0, ci)`;
        // reuse the same derivation against `lblk=0` so default policies
        // stay zero-IV while `IV_INO_LBLK_*` picks up the inode-derived
        // bytes.
        let iv = self.iv.xts_tweak(0);
        match &self.inner {
            FilenameCipherInner::AesCts256(k) => {
                let pt = cts::decrypt_cs3::<Aes256>(&**k, &iv, on_disk)?;
                out.extend_from_slice(&pt);
            }
            FilenameCipherInner::AesCts128(k) => {
                let pt = cts::decrypt_cs3::<Aes128>(&**k, &iv, on_disk)?;
                out.extend_from_slice(&pt);
            }
            FilenameCipherInner::Sm4Cts(k) => {
                let pt = cts::decrypt_cs3::<Sm4>(&**k, &iv, on_disk)?;
                out.extend_from_slice(&pt);
            }
            FilenameCipherInner::Adiantum(cipher) => {
                out.extend_from_slice(on_disk);
                // Adiantum's 32-byte tweak == kernel `union fscrypt_iv`
                // raw view at lblk=0. For DIRECT_KEY this carries the
                // ci_nonce in bytes 8..24; for default policies bytes
                // 8..32 are zero.
                let adi_tweak: [u8; ADIANTUM_TWEAK_SIZE] = self.iv.full_iv(0);
                cipher.decrypt_in_place(&adi_tweak, out)?;
            }
            FilenameCipherInner::Hctr2(cipher) => {
                out.extend_from_slice(on_disk);
                // HCTR2's 32-byte tweak (`TWEAK_SIZE` in kernel
                // `crypto/hctr2.c`) is the same `union fscrypt_iv` raw
                // view used by Adiantum. For default policies bytes
                // 8..32 are zero; IV_INO_LBLK_* / DIRECT_KEY are
                // rejected by validate_supported for HCTR2, so the
                // nonce-bearing variants cannot reach this arm.
                let h_tweak: [u8; HCTR2_TWEAK_SIZE] = self.iv.full_iv(0);
                cipher.decrypt_in_place(&h_tweak, out)?;
            }
        }
        while let Some(&0) = out.last() {
            out.pop();
        }
        Ok(())
    }

    /// Convenience wrapper for call sites that do not already carry a
    /// scratch buffer.
    pub(crate) fn decrypt_name(&self, on_disk: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::with_capacity(on_disk.len());
        self.decrypt_name_into(on_disk, &mut out)?;
        Ok(out)
    }
}

/// Build a fully-constructed [`FilenameCipher`] for the given inode +
/// policy + keystore.
///
/// `inode_number` is the inode that anchors the cipher — typically the
/// directory (for dirent decryption) or symlink (for symlink-target
/// decryption). For `IV_INO_LBLK_*` policies, the IV depends on this
/// inode number; for default policies, the IV is zero and the inode
/// number is used for error context only.
pub(crate) fn build_filename_cipher_for_inode(
    ext: &Ext,
    inode_number: u32,
    p: &FscryptPolicy,
) -> Result<FilenameCipher> {
    use crate::fscrypt::policy::{
        FSCRYPT_POLICY_FLAG_DIRECT_KEY, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
    };
    use zeroize::Zeroizing;

    policy::validate_supported(
        p,
        inode_number,
        ext.block_size.trailing_zeros() as u8,
        ext.compat
            .contains(crate::feature_flags::CompatFeatures::STABLE_INODES),
    )?;
    let iv64 = p.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 != 0;
    let iv32 = p.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 != 0;
    let direct = p.flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY != 0;
    // validate_supported guarantees a known mode, so this is `Some`.
    let key_size =
        mode_keysize(p.filenames_mode).expect("validate_supported guarantees a known mode");
    // Heap derivation buffer in `Zeroizing` so the bytes are scrubbed
    // once `FilenameCipher::new` copies them into a fixed-size cipher
    // state.
    let (raw_key, iv): (Zeroizing<alloc::vec::Vec<u8>>, IvDerivation) = if direct {
        // validate_supported has restricted DIRECT_KEY to v2 +
        // (Adiantum, Adiantum). Mirror kernel
        // `setup_per_mode_enc_key(HKDF_CONTEXT_DIRECT_KEY,
        // include_fs_uuid=false)`: HKDF info = [mode_num] only. The
        // per-file nonce enters via the IV (`fscrypt_generate_iv` writes
        // ci_nonce into bytes 8..24), not the key derivation.
        let id = p.key_identifier.expect("v2 policy carries identifier");
        let mk = ext
            .fscrypt_keys
            .get_v2(&id)?
            .ok_or_else(|| ExtError::MissingFscryptKey {
                inode: inode_number,
                policy_kind: alloc::format!("{:?}", p.kind),
                key_ref: hex(&id.0),
            })?;
        let key_bytes = kdf_v2::derive_direct_key(mk, p.filenames_mode, key_size);
        let iv = IvDerivation::DirectKey { nonce: p.nonce };
        (Zeroizing::new(key_bytes), iv)
    } else if iv64 || iv32 {
        let id = p.key_identifier.expect("v2 policy carries identifier");
        let mk = ext
            .fscrypt_keys
            .get_v2(&id)?
            .ok_or_else(|| ExtError::MissingFscryptKey {
                inode: inode_number,
                policy_kind: alloc::format!("{:?}", p.kind),
                key_ref: hex(&id.0),
            })?;
        let uuid = ext.uuid();
        let key_bytes = if iv64 {
            kdf_v2::derive_iv_ino_lblk_64_key(mk, p.filenames_mode, uuid, key_size)
        } else {
            kdf_v2::derive_iv_ino_lblk_32_key(mk, p.filenames_mode, uuid, key_size)
        };
        let iv = if iv64 {
            IvDerivation::InoLblk64 { inode_number }
        } else {
            let ino_hash_key = kdf_v2::derive_inode_hash_key(mk);
            let hashed_ino = crate::fscrypt::dirhash::inode_hash_low32(&ino_hash_key, inode_number);
            IvDerivation::InoLblk32 { hashed_ino }
        };
        (Zeroizing::new(key_bytes), iv)
    } else {
        let bytes =
            match p.kind {
                FscryptPolicyKind::V1 => {
                    let desc = p.key_descriptor.expect("v1 policy carries descriptor");
                    let mk = ext.fscrypt_keys.get_v1(&desc).ok_or_else(|| {
                        ExtError::MissingFscryptKey {
                            inode: inode_number,
                            policy_kind: alloc::format!("{:?}", p.kind),
                            key_ref: hex(&desc.0),
                        }
                    })?;
                    kdf_v1::derive(mk, &p.nonce, key_size)?
                }
                FscryptPolicyKind::V2 => {
                    let id = p.key_identifier.expect("v2 policy carries identifier");
                    let mk = ext.fscrypt_keys.get_v2(&id)?.ok_or_else(|| {
                        ExtError::MissingFscryptKey {
                            inode: inode_number,
                            policy_kind: alloc::format!("{:?}", p.kind),
                            key_ref: hex(&id.0),
                        }
                    })?;
                    kdf_v2::derive(mk, kdf_v2::ctx::PER_FILE_ENC_KEY, &p.nonce, key_size)
                }
            };
        (Zeroizing::new(bytes), IvDerivation::PerFileBlockIndex)
    };
    FilenameCipher::new(p, &raw_key, iv)
}

fn hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("string write infallible");
    }
    s
}

/// Cached crypto state for a directory iterator.
///
/// Captured once when the iterator is built so that every emitted entry
/// can be decrypted (or forwarded as ciphertext) without re-deriving
/// the filenames key on every step.
pub(crate) enum DirCryptoState {
    /// Directory is plaintext; iterator emits on-disk bytes directly.
    Plaintext,
    /// Directory is encrypted and a key is registered; iterator decrypts
    /// each name via the cipher.
    EncryptedDecryptable { cipher: FilenameCipher },
    /// Directory is encrypted but no key is registered. The default API
    /// path errors with `MissingFscryptKey` before iteration starts; the
    /// raw API path forwards the on-disk ciphertext bytes.
    EncryptedMissingKey {
        policy_kind: FscryptPolicyKind,
        key_ref: alloc::string::String,
    },
}

/// Compute the [`DirCryptoState`] for a directory inode.
pub(crate) fn directory_decryption_state<R: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut R,
    dir_inode: &crate::inode::ExtInode<'_>,
) -> Result<DirCryptoState> {
    use crate::inode::InodeFlags;
    if !dir_inode.flags().contains(InodeFlags::ENCRYPT_FL) {
        return Ok(DirCryptoState::Plaintext);
    }
    let p = dir_inode
        .fscrypt_policy(fs)?
        .ok_or(ExtError::InvalidFscryptPolicy {
            inode: dir_inode.inode_number(),
            reason: "ENCRYPT_FL set but missing context",
        })?;
    // The kernel rejects ENCRYPT_FL+CASEFOLD_FL with v1 policies because
    // there is no v1 path to derive a dirhash key. Reject the
    // combination here so a crafted on-disk image cannot proceed through
    // dirent decryption with v1 keys silently.
    if dir_inode.flags().contains(InodeFlags::CASEFOLD_FL) && p.kind == FscryptPolicyKind::V1 {
        return Err(ExtError::InvalidFscryptPolicy {
            inode: dir_inode.inode_number(),
            reason: "v1 policy on casefolded directory not supported by kernel",
        });
    }
    match build_filename_cipher_for_inode(ext, dir_inode.inode_number(), &p) {
        Ok(cipher) => Ok(DirCryptoState::EncryptedDecryptable { cipher }),
        Err(ExtError::MissingFscryptKey { key_ref, .. }) => {
            Ok(DirCryptoState::EncryptedMissingKey {
                policy_kind: p.kind,
                key_ref,
            })
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AES-256-CBC ciphertext of "hello.txt\0\0\0\0\0\0\0" (16-byte block,
    /// 7 NUL-byte pad) under the 32-byte all-zero key with a 16-byte
    /// zero IV. For a single 16-byte block, CS3 collapses to plain CBC.
    ///
    /// Computed via:
    ///     openssl enc -aes-256-cbc -nopad -K 00..00 -iv 00..00
    const REFERENCE_NAME_CT_HEX: &str = "7c3b53a612599fe218b2c2e2aebc9cf5";

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn filename_cipher_adiantum_strips_padding() {
        use crate::fscrypt::adiantum::ADIANTUM_KEY_SIZE;
        use crate::fscrypt::types::{
            FSCRYPT_MODE_ADIANTUM, FscryptKeyIdentifier, FscryptPolicy, FscryptPolicyKind,
        };

        const KEY: [u8; ADIANTUM_KEY_SIZE] = [0u8; ADIANTUM_KEY_SIZE];
        // Full filename correctness is verified by the integration tests
        // against the kernel-produced fixture. This unit test pins the
        // typed dispatch path and confirms the Adiantum arm accepts a
        // minimum-size ciphertext buffer.

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
        let cipher = FilenameCipher::new(&policy, &KEY, IvDerivation::PerFileBlockIndex).unwrap();
        let buf = [0u8; 16];
        cipher
            .decrypt_name(&buf)
            .expect("Adiantum FilenameCipher accepts minimum-size ciphertext");
    }

    #[test]
    fn filename_cipher_aes128_cts_round_trips_single_block() {
        // Single 16-byte block = plain CBC with the 16-byte zero IV
        // (CS3 collapses for n == 16). Encrypt locally with AES-128 then
        // decrypt via the typed dispatch path.
        use crate::fscrypt::types::{
            FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS, FscryptKeyIdentifier,
        };
        use aes::Aes128;
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt, KeyInit};

        let key = [0x11u8; 16];

        let mut block = {
            let mut p = [0u8; 16];
            p[..b"hello.txt".len()].copy_from_slice(b"hello.txt");
            p
        };
        let aes = Aes128::new_from_slice(&key).expect("16-byte key valid");
        aes.encrypt_block(GenericArray::from_mut_slice(&mut block));

        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_128_CBC,
            filenames_mode: FSCRYPT_MODE_AES_128_CTS,
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let cipher = FilenameCipher::new(&policy, &key, IvDerivation::PerFileBlockIndex).unwrap();
        let pt = cipher.decrypt_name(&block).unwrap();
        assert_eq!(pt.as_slice(), b"hello.txt");
    }

    #[test]
    fn filename_cipher_new_rejects_wrong_key_size() {
        // AES-128-CTS expects 16 bytes; passing 32 must fail-closed.
        use crate::fscrypt::types::{
            FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS, FscryptKeyIdentifier,
        };
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_128_CBC,
            filenames_mode: FSCRYPT_MODE_AES_128_CTS,
            flags: 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        let result = FilenameCipher::new(&policy, &[0u8; 32], IvDerivation::PerFileBlockIndex);
        assert!(matches!(
            result.err(),
            Some(ExtError::InvalidFscryptPolicy { .. })
        ));
    }

    #[test]
    fn decrypt_name_strips_trailing_nul_padding() {
        let key = [0u8; 32];
        let ct = hex(REFERENCE_NAME_CT_HEX);
        let pt = decrypt_name(&key, &ct).unwrap();
        assert_eq!(pt.as_slice(), b"hello.txt");
    }
}
