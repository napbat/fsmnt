//! No-key encoded directory entry / symlink target encoding.
//!
//! Mirrors the kernel's `fscrypt_fname_disk_to_usr` no-key branch: when
//! an encrypted name is read without the master key, the kernel emits
//! `base64url(fscrypt_nokey_name)` — a stable ASCII presentation of the
//! ciphertext that fits within `NAME_MAX` and survives `readdir`.
//!
//! Kernel reference (v6.17): `fs/crypto/fname.c` lines 295-350 and
//! `fs/crypto/fscrypt_private.h` lines 40-51 (struct definition).

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Length of the inline ciphertext slot inside `fscrypt_nokey_name`.
///
/// Mirrors `sizeof(((struct fscrypt_nokey_name *)0)->bytes)` from
/// `fs/crypto/fscrypt_private.h`.
const NOKEY_INLINE_BYTES: usize = 149;

/// Total wire size of `fscrypt_nokey_name` when the SHA-256 tail is in
/// use: 8 (dirhash) + 149 (bytes) + 32 (sha256) = 189.
///
/// Kernel symbol: `FSCRYPT_NOKEY_NAME_MAX`.
const NOKEY_NAME_MAX: usize = 8 + NOKEY_INLINE_BYTES + 32;

/// RFC 4648 §5 URL-safe base64 alphabet (no padding).
///
/// Mirrors `base64url_table` referenced by `fscrypt_base64url_encode`
/// (`fs/crypto/fname.c`).
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `src` as base64url with no `=` padding.
///
/// Bit-for-bit equivalent to `fscrypt_base64url_encode` in
/// `fs/crypto/fname.c` lines 164-180: bytes are streamed MSB-first into
/// a 32-bit accumulator and emitted as 6-bit groups; any trailing bits
/// at the end (2 or 4) are left-aligned and emitted as one final char.
fn base64url_encode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
    let mut ac: u32 = 0;
    let mut bits: u32 = 0;
    for &b in src {
        ac = (ac << 8) | u32::from(b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(BASE64URL[((ac >> bits) & 0x3f) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE64URL[((ac << (6 - bits)) & 0x3f) as usize]);
    }
    out
}

/// Encode an encrypted name as `base64url(fscrypt_nokey_name)`.
///
/// Mirrors the no-key branch of `fscrypt_fname_disk_to_usr`
/// (`fs/crypto/fname.c` lines 295-350). The on-disk struct is laid out
/// as `dirhash[2] (LE u32 × 2) || ciphertext_or_first_149_bytes
/// || optional sha256(ciphertext_tail)`.
///
/// `dirhash` mirrors the kernel's `(hash, minor_hash)` arguments; ext4
/// passes `(0, 0)` for non-casefolded encrypted directories. Casefold
/// directories carry the dirhash inside each on-disk dirent — that
/// extraction is filed as a follow-up; this encoder accepts whatever
/// the caller supplies so future casefold support drops in cleanly.
pub(crate) fn encode_nokey_name(dirhash: [u32; 2], ciphertext: &[u8]) -> Vec<u8> {
    let mut wire = [0u8; NOKEY_NAME_MAX];
    wire[0..4].copy_from_slice(&dirhash[0].to_le_bytes());
    wire[4..8].copy_from_slice(&dirhash[1].to_le_bytes());

    let size = if ciphertext.len() <= NOKEY_INLINE_BYTES {
        let end = 8 + ciphertext.len();
        wire[8..end].copy_from_slice(ciphertext);
        end
    } else {
        wire[8..8 + NOKEY_INLINE_BYTES].copy_from_slice(&ciphertext[..NOKEY_INLINE_BYTES]);
        let tail_hash = Sha256::digest(&ciphertext[NOKEY_INLINE_BYTES..]);
        wire[8 + NOKEY_INLINE_BYTES..NOKEY_NAME_MAX].copy_from_slice(&tail_hash);
        NOKEY_NAME_MAX
    };

    base64url_encode(&wire[..size])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checked against `base64.urlsafe_b64encode(b"Hi!").rstrip(b"=")`.
    #[test]
    fn base64url_short_inputs_match_python_reference() {
        assert_eq!(base64url_encode(b""), b"");
        assert_eq!(base64url_encode(b"Hi!"), b"SGkh");
        // 4-byte input → 6 chars, no `=` padding.
        assert_eq!(base64url_encode(b"hell"), b"aGVsbA");
    }

    /// Short ct path: `dirhash=zero || 16 bytes 0x00..0x0f`.
    /// Reference computed via Python (see plan).
    #[test]
    fn nokey_short_matches_python_reference() {
        let ct: [u8; 16] = core::array::from_fn(|i| i as u8);
        let encoded = encode_nokey_name([0, 0], &ct);
        assert_eq!(&encoded, b"AAAAAAAAAAAAAQIDBAUGBwgJCgsMDQ4P");
    }

    /// Boundary at exactly 149 bytes — still inline, no SHA-256 tail.
    #[test]
    fn nokey_at_inline_boundary_uses_inline_path() {
        let ct = [0xAAu8; NOKEY_INLINE_BYTES];
        let encoded = encode_nokey_name([0, 0], &ct);
        // ceil((8 + 149) * 4 / 3) = ceil(157 * 4 / 3) = 210 chars.
        assert_eq!(encoded.len(), 210);
    }

    /// Long ct path: 200-byte ct → 189-byte struct → 252 base64url chars.
    /// Reference computed via Python with ct[i] = (i*7 + 13) & 0xFF.
    #[test]
    fn nokey_long_uses_sha256_tail() {
        let ct: Vec<u8> = (0..200u32).map(|i| ((i * 7 + 13) & 0xFF) as u8).collect();
        let encoded = encode_nokey_name([0, 0], &ct);
        assert_eq!(encoded.len(), 252);
        let expected: &[u8] = b"AAAAAAAAAAANFBsiKTA3PkVMU1phaG92fYSLkpmgp661vMPK0djf5u30-wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWco6qxuL_GzdTb4unw9_4FDBMaISgvNj1ES1JZYGdudXyDipGYn6attLvCydDX3uXs8_oBCA8WHSQrMjlAR05VXGNqcXh_ho2Um6KpsLe-xczT2uHo7_b9BAsSGZWHboiAOUMGEbyZBDckAUb-VTwC6QoDh7Q-LzSMfCKe";
        assert_eq!(encoded.as_slice(), expected);
    }

    /// Non-zero dirhash is emitted little-endian — kernel writes the
    /// raw `u32` directly into the struct, which on the supported
    /// targets means LE byte order.
    #[test]
    fn nokey_dirhash_emits_little_endian() {
        // dirhash=[0x01020304, 0x05060708] || empty ct → 8-byte struct.
        let encoded = encode_nokey_name([0x0102_0304, 0x0506_0708], &[]);
        // wire bytes: 04 03 02 01 08 07 06 05 → base64url:
        // 040302 = 0000 0100 0000 0011 0000 0010 = 1, 4, 0, 50 → BEDC … work it out
        // Easier: just pin against the Python reference.
        // python: base64.urlsafe_b64encode(bytes.fromhex('0403020108070605')).rstrip(b"=")
        // → "BAMCAQgHBgU"
        assert_eq!(&encoded, b"BAMCAQgHBgU");
    }
}
