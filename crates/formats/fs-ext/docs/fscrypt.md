# fscrypt support in fs-ext

Read-only Linux fscrypt v1 / v2 implementation for ext4 filesystems.
Mirrors the kernel's `fs/crypto/` and `fs/ext4/crypto.c` so a fixture
encrypted by a real Linux kernel decrypts byte-for-byte under fs-ext.

References:

- `Documentation/filesystems/fscrypt.rst` (kernel)
- `fs/crypto/{keysetup_v1,keysetup,policy,fname,hkdf}.c`
- `fs/ext4/crypto.c`, `fs/ext4/namei.c` (htree dispatch)

## Supported policy versions and modes

| dimension | supported              |
| --------- | ---------------------- |
| version   | v1 (kernel 4.0+), v2 (kernel 5.4+) |
| contents  | `FSCRYPT_MODE_AES_256_XTS` (1), `FSCRYPT_MODE_AES_128_CBC` (5) |
| filenames | `FSCRYPT_MODE_AES_256_CTS` (4), `FSCRYPT_MODE_AES_128_CTS` (6) |
| AES-128-CBC + AES-128-CTS (v1 and v2) | `essiv(cbc(aes))` for contents, `cts(cbc(aes))` for filenames. Default cipher on older Android (pre-AES-NI) and embedded ext4. |
| Adiantum | `adiantum(xchacha12, aes)` with `nhpoly1305`. Default cipher on Android devices lacking AES-NI. v1 and v2 supported. |
| SM4-XTS contents + SM4-CBC-CTS filenames (v2 only) | `xts(sm4)` for contents, `cts(cbc(sm4))` for filenames. Chinese-market devices and embedded ext4 deployments. |
| AES-256-XTS contents + AES-256-HCTR2 filenames (v2 only) | HCTR2 is the wide-block, length-preserving filenames cipher Android 14+ inline-crypto SoCs ship. Contents stay on the standard AES-256-XTS path. |
| flags     | any combination of `PAD_*` (`0x00..0x03`) -- padding is applied per `flags & 0x03`; v2 + AES-XTS/CTS may additionally set `IV_INO_LBLK_64` (`0x08`) or `IV_INO_LBLK_32` (`0x10`), but not both. v2 + Adiantum may set `DIRECT_KEY` (`0x04`); DIRECT_KEY is mutually exclusive with both IV_INO_LBLK_* flags. |
| dirhash   | SipHash-2-4 for v2+casefold via htree v6; classic dx_hash_legacy/half_md4 for unencrypted dirs |
| `log2_data_unit_size` | 0 (fs block size) or any value in [`SECTOR_SHIFT` (9), log2(fs_block_size)]; sub-block units require kernel ≥ 6.7 and are incompatible with `IV_INO_LBLK_64` / `IV_INO_LBLK_32` (the IV reserves only 32 bits for the data-unit index, which the kernel `fscrypt_max_file_dun_bits` guard rejects on filesystems whose max file size exceeds 2^32 data units — true for any ext4) |

Anything outside this matrix surfaces as `ExtError::UnsupportedFscryptMode`
or `ExtError::InvalidFscryptPolicy` at access time -- the filesystem
opens, but objects under the unsupported policy report the failure when
read.

## Key derivation

### v1 (`fscrypt::kdf_v1`)

Per-file encryption keys derive via AES-128-ECB:

1. Encrypt the master key (16 bytes used; 64-byte buffer zero-padded)
   under each 16-byte block of the per-file `nonce`, where the nonce
   acts as the AES-128 *key* and the master key bytes are the
   plaintext.
2. Concatenate the four resulting 16-byte blocks to form the 64-byte
   per-file key (filenames-key path mixes in the policy descriptor as
   the AAD in the same way).

### v2 (`fscrypt::kdf_v2`)

Per-file and filenames keys derive via HKDF-SHA512 with:

- salt = 64 zero bytes
- IKM  = master key (16..=64 bytes)
- info = `b"fscrypt\0"` || *context* || *application_info*

The kernel `KEY_IDENTIFIER` context (1) yields the 16-byte
`master_key_identifier` registered in the v2 keystore. Per-file
content keys use context 2 (`PER_FILE_ENC_KEY`) with the inode's nonce
as application_info; filenames keys use the same context against the
parent directory's nonce. DIRHASH_KEY (5) derives the SipHash key for
htree v6 lookup in casefold-encrypted directories.

Contexts 4 (`IV_INO_LBLK_64_KEY`), 6 (`IV_INO_LBLK_32_KEY`), and 7
(`INODE_HASH_KEY`) cover the inline-crypto policy flags described in
the next subsection. Context 3 (`DIRECT_KEY`) covers the Adiantum
direct-key mode described in the `DIRECT_KEY` subsection below.

### `IV_INO_LBLK_64` / `IV_INO_LBLK_32` (v2 + AES-XTS/CTS)

Modern Android (11+) configures fscrypt with one of these flags so a
single hardware-wrapped key can cover many files: the kernel switches
from per-file keys to a per-mode-per-FS key, and changes the IV from
the logical block index to a value derived from the inode number.
`fs-ext` reads policies with these flags using the same on-disk
formats:

- **Per-mode key**:
  `HKDF(master_key, context = IV_INO_LBLK_64_KEY | IV_INO_LBLK_32_KEY,
   info = [mode_num] || fs_uuid)`. The FS UUID is the 16-byte
  `superblock.s_uuid`; for filenames the mode_num is the policy's
  `filenames_mode`, for contents it is `contents_mode`.
- **`IV_INO_LBLK_64` content IV** (XTS tweak): low 8 bytes =
  little-endian `u64` of `(lblk_num & 0xFFFFFFFF) | (inode << 32)`,
  high 8 bytes zero.
- **`IV_INO_LBLK_32` content IV**: an additional per-FS 16-byte
  SipHash-2-4 key is derived (`HKDF` with `INODE_HASH_KEY` context,
  empty info); `hashed_ino = u32(siphash24(le8(inode), key))` then the
  XTS tweak's low 8 bytes are
  `(lblk_num as u32).wrapping_add(hashed_ino) as u64` (LE).
- **Filename IV**: filenames call the same IV generator with `lblk=0`.
  Default policies therefore use a zero IV; `IV_INO_LBLK_64` uses
  `inode << 32`, and `IV_INO_LBLK_32` uses `hashed_ino`.
- Setting both `IV_INO_LBLK_64` and `IV_INO_LBLK_32` simultaneously
  is rejected. So is `IV_INO_LBLK_*` on a v1 policy or with
  Adiantum contents.
- **Stable-inode requirement**: kernel
  `supported_iv_ino_lblk_policy` (`fs/crypto/policy.c`) calls
  `sb->s_cop->has_stable_inodes(sb)` and rejects the policy when the
  hook is missing or returns false. ext4 wires that hook through
  `ext4_has_stable_inodes` →
  `EXT4_FEATURE_COMPAT_STABLE_INODES` (0x0800). fs-ext mirrors
  the same check: any `IV_INO_LBLK_*` policy on a filesystem
  without the `STABLE_INODES` compat bit is rejected fail-closed
  with `ExtError::UnsupportedFscryptMode`. Without that guarantee
  inode renumbering (e.g. via `tune2fs -E inode_resize`) would
  invalidate the IV and decrypt to wrong content.

### `DIRECT_KEY` (v2 + Adiantum)

Older Android (10-) ships fscrypt with the `FSCRYPT_POLICY_FLAG_DIRECT_KEY`
(`0x04`) flag on Adiantum-on-non-AES-NI hardware: instead of deriving a
per-file content/filename key from the inode nonce, the kernel uses a
per-mode key derived only from the master key, and shifts the per-file
nonce into the IV.

- **Per-mode key**: `HKDF(master_key, context = DIRECT_KEY,
  info = [mode_num])`. Unlike `IV_INO_LBLK_*`, the FS UUID is **not**
  included in the HKDF info — a single `mk_direct_keys` cache covers
  the master key + mode pair across any FS that holds it.
- **IV layout** (kernel `fscrypt_generate_iv`):
  - `memset(iv, 0, ivsize)` — Adiantum ivsize = 32.
  - `memcpy(iv->nonce, ci->ci_nonce, 16)` writes the per-file nonce
    into bytes 8..24 (offset of `union fscrypt_iv::nonce`).
  - `iv->index = cpu_to_le64(lblk_num)` writes the data-unit index
    into bytes 0..8.
  - Bytes 24..32 stay zero. Filenames call the same generator with
    `lblk = 0`, so the filename IV is `0x00 * 8 || ci_nonce_16 || 0x00 * 8`.
- **Mode constraints**: kernel `supported_direct_key_modes` requires
  `contents_mode == filenames_mode` AND
  `mode->ivsize >= offsetofend(union fscrypt_iv, nonce) = 24`. Of the
  modes fs-ext supports, only Adiantum (ivsize = 32) qualifies;
  AES-256-XTS (ivsize = 16) is rejected.
- **Mutual exclusion**: kernel `fscrypt_supported_v2_policy` rejects
  `DIRECT_KEY | IV_INO_LBLK_64` or `DIRECT_KEY | IV_INO_LBLK_32`
  (count > 1 across the three "key derivation strategy" flags).
- **Scope**: fs-ext implements DIRECT_KEY for v2 + (Adiantum, Adiantum)
  only, matching the only deployed combination on real fscrypt
  acquisitions. v1 + DIRECT_KEY (allowed by the kernel via
  `fscrypt_setup_v1_file_key_via_subscribed_keyrings`) is rejected
  fail-closed.

### Sub-block data units (`log2_data_unit_size`)

Kernel ≥ 6.7 lets a v2 policy encrypt files in chunks smaller than the
fs block size — e.g. 512 B units on a 4 KiB-block ext4 — by setting
`log2_data_unit_size` on the policy. The use case is inline-crypto
compatibility with storage devices that natively operate on 512 B
sectors. Filename and symlink encryption are unaffected (they always
use one block at `lblk=0`); only content decryption iterates per data
unit.

`fs-ext` walks each fs-block in `data_unit_size`-byte chunks during
content decryption. Each chunk uses its own IV derived from the
*absolute* data-unit index — i.e. `block_index * (block_size /
data_unit_size) + chunk_index`. The IV-derivation strategy
(`PerFileBlockIndex`, `IV_INO_LBLK_64`) is unchanged; only the index
it operates on shifts from fs-block to data unit.

Validation mirrors the kernel's `fscrypt_supported_v2_policy`:

- `log2_data_unit_size == 0` → use the fs block size.
- Otherwise, `SECTOR_SHIFT (9) ≤ value ≤ log2(fs_block_size)`.
- `IV_INO_LBLK_64` / `IV_INO_LBLK_32` + sub-block (i.e.
  `log2_data_unit_size != log2(fs_block_size)`) is rejected. Both flags
  reserve only 32 bits for the data-unit index, and the kernel's
  `fscrypt_max_file_dun_bits > 32` guard catches this for any
  filesystem whose max file size in data units exceeds `u32::MAX` —
  which is always true for ext4 (≥ 16 TiB) with sub-block DUS. The
  `IV_INO_LBLK_32` case is additionally documented in the kernel as
  "not yet supported".

## Filename encryption

`fscrypt::cts` implements AES-256-CBC-CTS (variant CS3 -- the kernel's
`cbc(aes)` + ciphertext-stealing wrapper). The encryption parameters:

- 32-byte key derived above
- 16-byte IV = `fscrypt_generate_iv(0)`: zero for default policies,
  inode-derived for `IV_INO_LBLK_*`
- plaintext is the directory entry name, NUL-padded up to the next
  multiple of `4 << (flags & 0x03)` (PAD_4 / PAD_8 / PAD_16 / PAD_32)
- ciphertext length matches plaintext length (CS3 keeps length intact)

When the fs-ext keystore has no key for the policy referenced by an
encrypted directory, raw entry iteration (`raw_entries`) yields the
on-disk ciphertext bytes; high-level iteration (`entries`) returns
`ExtError::MissingFscryptKey` with the v1 descriptor or v2 identifier
hex-encoded so callers can identify the missing key.

### No-key directory entry encoding

`ExtRawDirEntry::name_nokey_encoded()` returns the entry name in the
kernel's no-key presentation form — `base64url(fscrypt_nokey_name)`,
matching what a userspace `readdir()` sees on a kernel-mounted image
with no key registered. Mirrors `fs/crypto/fname.c::fscrypt_fname_disk_to_usr`
(v6.17 lines 295-350):

- 8-byte LE `dirhash[2]` (zero — see casefold note below)
- up to 149 bytes of inline ciphertext
- when ciphertext > 149 bytes, the tail is replaced by
  `sha256(ciphertext[149..])` (32 bytes) and the wire size becomes
  the maximum 189 bytes

The result is base64url-encoded with the RFC 4648 URL-safe alphabet
and no `=` padding (kernel `fscrypt_base64url_encode`,
`fs/crypto/fname.c` lines 164-180).

For unencrypted entries, `name_nokey_encoded()` returns a copy of
`name_bytes()` unchanged.

**Casefold limitation**: the kernel's `ext4_readdir`
(`fs/ext4/dir.c`) reads `dirhash[0..2]` from each on-disk dirent's
`EXT4_DIRENT_HASH` / `EXT4_DIRENT_MINOR_HASH` trailer when the
directory is both `IS_CASEFOLDED` and `IS_ENCRYPTED`. fs-ext currently
emits zero in those slots, which means listings of a casefolded
encrypted directory will not byte-match a kernel `readdir()`. Filed
as a separate follow-up.

## Symlink target framing

The on-disk `fscrypt_symlink_data` for an encrypted symlink is:

```
+----------------+--------------------------+
|  u16 LE length |  ciphertext (length B)   |
+----------------+--------------------------+
```

`fscrypt::symlink::decode_symlink` validates the length prefix against
the inode size, decrypts via the per-inode filenames key, and trims
trailing NUL padding to recover the original target.

When the registered keystore has no key for the symlink's policy,
[`ExtInode::read_symlink`] mirrors the kernel's
`fscrypt_get_symlink` (`fs/crypto/hooks.c`) → `fscrypt_fname_disk_to_usr`
no-key branch and returns `base64url(fscrypt_nokey_name)` over the
ciphertext bytes — the same stable ASCII string a kernel `readlink()`
produces. Same encoder as the no-key directory entry path
documented above. Wrong-key reads (fscrypt is unauthenticated) take the
existing decrypt branch and produce garbled plaintext rather than the
no-key form.

## Content encryption

`fscrypt::content` implements AES-256-XTS via the `xts-mode` crate.
Each filesystem block is treated as a separate XTS sector with:

- key = 64-byte content key (k1 || k2). Default and v1 policies use a
  per-file key derived from the inode's nonce. `IV_INO_LBLK_*` policies
  use a per-mode-per-FS key (see above).
- tweak: by default, the logical block index as a little-endian u64 in
  the low 8 bytes of the 16-byte tweak. Under `IV_INO_LBLK_64` the
  tweak is `(lblk & 0xFFFFFFFF) | (inode << 32)` (LE u64); under
  `IV_INO_LBLK_32` it is `(lblk as u32).wrapping_add(hashed_ino)`
  (LE u64). High 8 bytes of the tweak are always zero.

`ExtFile` contains an `Encrypted` backing variant that wraps the same
extent / block-map dispatch used for plaintext files; reads decrypt
each fs-block in place before the user's buffer copy. Streaming reads
that span multiple blocks decrypt each block independently because XTS
keeps each sector self-contained.

## AES-128-CBC contents (ESSIV)

`FSCRYPT_MODE_AES_128_CBC` (mode 5) ships on older Android (pre-AES-NI)
and embedded ext4. Unlike AES-256-XTS, the kernel registers the cipher
as `essiv(cbc(aes))`, so the per-block CBC IV is derived rather than
read directly from `union fscrypt_iv`:

- **Plain IV** — the kernel's standard `fscrypt_generate_iv` output
  (low 16 bytes of [`IvDerivation::full_iv`]). For default policies
  this is `lblk_le8 || zero_8`.
- **ESSIV salt cipher** — `AES-256-ECB` keyed with the **full**
  32-byte SHA-256 digest of the content key. The kernel uses
  `crypto_cipher_setkey(essiv_cipher, salt, crypto_shash_digestsize(sha256))`
  in `crypto/essiv.c::essiv_skcipher_setkey` (line 91), so the inner
  cipher's key length matches the hash output, not the content
  cipher's 16-byte key.
- **Per-block CBC IV** — `essiv_iv = AES-256-ECB(SHA-256(content_key))(plain_iv)`.
- **Data unit** — CBC-decrypt the whole data unit (4096 B for default
  policies; one chain per unit for sub-block DUS, with a fresh ESSIV
  derivation per unit) under the AES-128 content key with `essiv_iv`.

Filenames pair with `FSCRYPT_MODE_AES_128_CTS` (mode 6) — the same
CS3 wrapper used by AES-256-CTS, just keyed with 16 bytes. fs-ext's
`cts::decrypt_cs3` is generic over the AES variant so both share one
implementation.

`IV_INO_LBLK_64` / `IV_INO_LBLK_32` are not allowed with AES-128-CBC
(kernel `fscrypt_supported_iv_ino_lblk_policy` only wires those flags
for AES-256-XTS contents). DIRECT_KEY likewise stays out: kernel
`supported_direct_key_modes` requires `mode->ivsize >= 24`, but
AES-128-CBC's ivsize is 16.

## SM4-XTS contents + SM4-CBC-CTS filenames

`FSCRYPT_MODE_SM4_XTS` (mode 7) and `FSCRYPT_MODE_SM4_CTS` (mode 8) are
the Chinese national block cipher modes the kernel ships for SM4-bound
hardware (mainly Chinese-market phones and embedded systems). Per kernel
`fscrypt_valid_enc_modes_v2` (lines 88-90), the only valid pair is
`(SM4_XTS, SM4_CTS)` — v2-only (`fscrypt_valid_enc_modes_v1` does not
list SM4).

Implementation reuses every shared piece:

- **Content cipher** — `xts-mode::Xts128<Sm4>` from the same crate
  already used for AES-256-XTS. Two SM4-128 keys (`k1 || k2`, 32 bytes
  total per kernel `fscrypt_modes` keysize=32). Tweak shape is
  identical to AES-256-XTS — only the inner block cipher swaps.
- **Filename cipher** — `cts::decrypt_cs3::<Sm4>` against the same
  generic CS3 (CBC-CTS) implementation already used for AES-256-CTS
  and AES-128-CTS. SM4 has the same 16-byte block size, so the CS3
  layout is byte-for-byte identical.

`IV_INO_LBLK_*` is rejected for SM4 fail-closed because kernel
`supported_iv_ino_lblk_policy` requires AES-256-XTS contents. DIRECT_KEY
is also rejected (the existing branch only allows Adiantum). v1 + SM4
is rejected fail-closed.

The single new dependency is `sm4 = "0.5"` (RustCrypto, well-vetted,
on the same `cipher 0.4` generation as `aes 0.8`).

## AES-256-HCTR2 filenames (`hctr2(aes)`)

`FSCRYPT_MODE_AES_256_HCTR2` (mode 10) is paired with AES-256-XTS contents
on v2 policies (kernel `fscrypt_valid_enc_modes_v2` lines 84-86). HCTR2 is
the wide-block cipher; the kernel uses it as the **filenames** cipher because
length-preserving deterministic encryption is what htree lookup needs. The
contents path stays on standard AES-256-XTS (already supported).

HCTR2 is built from three primitives:

- **AES-256** (E for setup + finish, D for the middle pass, plus
  E for the XCTR keystream).
- **POLYVAL** universal hash (RustCrypto `polyval` crate; matches kernel
  `crypto/polyval-generic.c` semantics — RFC 8452 byte order, no GHASH
  bit/byte reversal).
- **XCTR**: counter mode but with `keystream = E(IV ⊕ counter)` instead
  of `E(IV + counter)` (kernel `crypto/xctr.c`). Counter is `i + 1` as
  little-endian `u32` XOR'd into the first 4 bytes of the IV.

Decrypt for ciphertext `C` with tweak `T` (32 bytes from
[`IvDerivation::full_iv(0)`]):

```
H = AES_256_E_K(zero[16])               // POLYVAL key, derived once
L = AES_256_E_K([0x01 || zero[15]])     // XCTR IV mask, derived once

U = C[0..16]; V = C[16..]
h_TV = POLYVAL(H, len_block || T || V_padded)
UU   = U ^ h_TV
MM   = AES_256_D_K(UU)
S    = MM ^ UU ^ L
N    = V ^ XCTR_K(S, |V|)
h_TN = POLYVAL(H, len_block || T || N_padded)
M    = MM ^ h_TN
```

`len_block` is 16 bytes: `cpu_to_le64(TWEAK_BITS * 2 + 2 + has_remainder)
|| zero[8]`, where `has_remainder = (|V| % 16 != 0)`. The bulk
remainder is HCTR2-padded with `0x01 || zero...` to fill a POLYVAL
block (NOT zero-padded).

`fs-ext`'s implementation in `crates/fs-ext/src/fscrypt/hctr2.rs` is a
direct port of kernel `crypto/hctr2.c` + `crypto/xctr.c`, validated
against the kernel `aes_hctr2_tv_template` AES-256 vectors at
len=16 / len=17 / len=31 (covering the no-remainder, 1-byte-tail, and
15-byte-tail XCTR paths).

`IV_INO_LBLK_*` is rejected for HCTR2 fail-closed even though the
kernel allows it (the kernel `supported_iv_ino_lblk_policy` whitelists
XTS contents, which (XTS, HCTR2) satisfies). Issue #153 scopes that
combination as a separate follow-up.

## Adiantum (`adiantum(xchacha12, aes)`)

Length-preserving wide-block cipher built from XChaCha12, single-block
AES-256, and the NHPoly1305 ε-AΔU universal hash. fscrypt enables it on
hardware that lacks AES-NI / ARMv8 crypto extensions — typically lower-
end Android phones. `fs-ext` supports Adiantum read-only under both v1
and v2 policies; the kernel `fscrypt_valid_enc_modes_v1` whitelists the
(Adiantum, Adiantum) pair on v1.

Tweak size is 32 bytes (`.ivsize`). For file contents, the tweak is
`lblk_u64.to_le_bytes() || [0u8; 24]`. For filenames and symlink
targets, the tweak is all zero.

Reference: Linux `crypto/adiantum.c`, `crypto/nhpoly1305.c`. Original
paper: Crowley & Biggers, IACR ePrint 2018/720.

## Casefold + encryption (#123)

When a directory carries both `EXT4_CASEFOLD_FL` and `EXT4_ENCRYPT_FL`,
ext4 switches to **htree version 6**: directory entries are indexed by
SipHash-2-4 of the *plaintext* name keyed with a per-directory dirhash
key (HKDF context 5, `DIRHASH_KEY`). `fscrypt::dirhash::siphash24`
implements the primitive; `crate::htree` dispatches to it via
`dirhash_key_for_directory`. Lookup decrypts entries as it goes so
callers compare plaintext UTF-8 (or its NFD-folded form for casefold).

## Hardware-wrapped master keys (Android 12+)

Modern Android (12+) registers fscrypt master keys with the kernel in
**wrapped** form: a TEE / Keymaster / Keymint-bound blob that only a
trusted execution environment can unwrap into the actual fscrypt master
key bytes. fs-ext supports this via a deferred-unwrap path so operators
don't have to materialize the unwrapped key at registration time.

### Registration

```rust,ignore
use fs_ext::{Ext, FscryptKeyIdentifier, FscryptKeyUnwrapper, FscryptKeyUnwrapError, FscryptMasterKey};

struct KeymintAdapter { /* TEE handle */ }
impl FscryptKeyUnwrapper for KeymintAdapter {
    fn unwrap_key(&self, wrapped: &[u8]) -> Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        let raw = self.tee_unwrap(wrapped)
            .map_err(|e| FscryptKeyUnwrapError::new(format!("Keymint: {e}")))?;
        FscryptMasterKey::from_bytes(&raw)
            .map_err(|e| FscryptKeyUnwrapError::new(format!("{e:?}")))
    }
}

ext.add_fscrypt_v2_wrapped_key(
    identifier,                                  // 16-byte v2 identifier
    wrapped_blob,                                // operator-supplied bytes
    Box::new(KeymintAdapter { /* … */ }),
);
```

### Lifecycle

1. `add_fscrypt_v2_wrapped_key` stores the wrapped blob, the unwrapper,
   and an empty `OnceCell` for the unwrapped key under the supplied
   identifier. No unwrap call yet.
2. The first `get_v2(identifier)` triggered by an inode lookup
   invokes the unwrapper, derives the v2 identifier from the resulting
   master key, and verifies it matches the registered identifier
   (defensive check against operator misconfiguration). On success the
   unwrapped key is cached in the `OnceCell` and returned.
3. Subsequent lookups return the cached key directly — the unwrapper
   is invoked **at most once per registered key per session**.
4. When the keystore drops, both the wrapped blob and the cached
   unwrapped key are zeroized via their `Zeroizing` / `ZeroizeOnDrop`
   wrappers.

### Errors

Unwrap failures surface as a new error variant:

- `ExtError::FscryptKeyUnwrapFailed { policy_kind, key_ref, reason }`
  — the operator's `unwrap_key` returned `Err`, OR the unwrapped key
  derived an identifier that doesn't match the registered one. The
  `reason` field carries the operator's error string verbatim, with
  the registered identifier in `key_ref`.
- `ExtError::MissingFscryptKey` continues to mean "no entry registered
  at all under this identifier" — i.e. the operator never called
  `add_fscrypt_v2_*_key` for it.

`inode` is `0` in `FscryptKeyUnwrapFailed` because the keystore lookup
itself doesn't see the calling inode; the actionable identifier lives
in `key_ref`.

### Identifier verification

The identifier-mismatch check is mandatory. fscrypt is unauthenticated,
so a wrapped blob registered under the wrong identifier would otherwise
unwrap to a key that decrypts the wrong inode's content into garbled
plaintext (no MAC to catch it). Catching the mismatch at the keystore
layer fails fast and points the operator at the misconfiguration.

### Thread-safety

`FscryptKeyUnwrapper: Send + Sync` is a trait bound, because `Ext` is
required to be `Send` by `agent-core`'s `TargetFilesystem` contract
(the trait object lives inside the keystore which lives inside `Ext`).
Real TEE adapters are typically stateless wrappers around an OS handle
and satisfy these bounds trivially; if your adapter holds non-`Sync`
state, wrap it in `Arc<Mutex<_>>` or similar before implementing the
trait.

### Out of scope

fs-ext does not parse or unwrap Keymaster / Keymint blob formats
itself — that requires TEE / device cooperation. The operator's
`FscryptKeyUnwrapper` adapter owns that logic. fs-ext provides the
trait contract, the lazy-cache machinery, and the error pathway.

## Wrong-key behaviour

fscrypt is **not** authenticated -- there's no MAC, GCM tag, or other
integrity check. Reading an encrypted file with the wrong key succeeds
without error and yields garbled bytes. The
`wrong_key_returns_garbled_content` integration test pins this
expectation. Callers needing tamper detection must layer their own
integrity check above fs-ext.

The same caveat applies to Adiantum: it is unauthenticated, so a wrong
master key produces decryption that returns garbage bytes rather than
an error. There is no integrity tag to detect the wrong-key case.

## Out of scope

The kernel supports several modes and policy flags that fs-ext does
not:

- `FSCRYPT_POLICY_FLAG_DIRECT_KEY` outside v2 + (Adiantum, Adiantum) --
  unsupported (the kernel allows DIRECT_KEY on v1 too, but no real
  fscrypt acquisition has been observed pairing it that way)

Encountering any of these surfaces as `UnsupportedFscryptMode` or
`InvalidFscryptPolicy`, never as silent garbage.

## Security notes

- `FscryptMasterKey` zeroizes its buffer on drop via `zeroize::ZeroizeOnDrop`
  and prints as `<redacted, N bytes>` from `Debug`.
- `FscryptKeyDescriptor` and `FscryptKeyIdentifier` implement
  `subtle::ConstantTimeEq`; the `BTreeMap` keystore lookup itself is
  not constant-time (the variants used as keys, by contract, are not
  secret), but ad-hoc descriptor / identifier comparisons in user code
  should prefer `ct_eq` to avoid leaking timing about which keys are
  registered.
- All keys are supplied out-of-band; fs-ext does no auto-discovery and
  does not touch the kernel keyring. Operators feed master keys via
  `Ext::add_fscrypt_v1_key` / `add_fscrypt_v2_key`.

## Worked example: traverse an encrypted directory

```rust,ignore
use fs_ext::{Ext, FscryptKeyDescriptor, FscryptMasterKey};
use sha2::{Digest, Sha512};

let mut fs = std::fs::File::open("ext4-fscrypt.img")?;
let mut ext = Ext::new(&mut fs)?;

// Reconstruct the master keys from out-of-band material. Real
// operators would read these from a key-management system; this
// example uses the same SHA-512 derivation our test fixture uses.
let mut hasher = Sha512::new();
hasher.update(b"tracium-fscrypt-v1-fixture");
let mut k = [0u8; 64];
k.copy_from_slice(&hasher.finalize());
ext.add_fscrypt_v1_key(
    FscryptKeyDescriptor([0xAA; 8]),
    FscryptMasterKey::from_array(k),
)?;

// Encrypted directory entries now decode transparently.
let mut root = ext.root_directory();
let v1_dir = root.lookup(&mut fs, b"v1_dir")?;
let mut dir = ext.directory_at(v1_dir.inode_number);
let hello = dir.lookup(&mut fs, b"hello.txt")?;
let inode = ext.inode(&mut fs, hello.inode_number)?;
let mut file = inode.open_file()?;
// `file.read_exact(&mut fs, &mut buf)?` returns plaintext bytes.
```

If the key is missing, `lookup` and content reads return
`ExtError::MissingFscryptKey { policy_kind, key_ref, .. }` with
`key_ref` set to the lowercase-hex v1 descriptor (8 bytes -> 16 chars)
or v2 identifier (16 bytes -> 32 chars), so the operator can
unambiguously identify which key needs to be supplied.
