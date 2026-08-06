# `ext4-fscrypt.img`

Deterministic ext4 image with up to twelve encrypted directories — one
v1, one v1+Adiantum, one v2, one v2+casefold, one v2+Adiantum, one
each for v2 + `IV_INO_LBLK_64` and v2 + `IV_INO_LBLK_32`, one v2 with
`log2_data_unit_size = 9` (512 B sub-block units), one v2 +
(Adiantum, Adiantum) + `DIRECT_KEY`, one v2 + (AES-128-CBC, AES-128-CTS),
one v2 + (SM4-XTS, SM4-CBC-CTS) (kernel with `CONFIG_CRYPTO_SM4`),
and one v2 + (AES-256-XTS, AES-256-HCTR2) (kernel ≥ 6.0 with
`CONFIG_CRYPTO_HCTR2`) — covering every #121 acceptance criterion
plus #123's combined `ENCRYPT_FL`+`CASEFOLD_FL` path, #143's Adiantum
mode, #144's inline-crypto policy flags, #157's v1+Adiantum combination,
#155's sub-block data units, #154's DIRECT_KEY mode, #151's
AES-128-CBC-ESSIV / AES-128-CTS pair, #152's SM4 pair, and #153's
AES-256-HCTR2 filenames pair. The SM4 and HCTR2 directories are
skipped at fixture-gen time when the kernel lacks the required cipher
module; fs-ext integration tests skip the corresponding cases when
the directory is absent.

## Generation

```
sudo bash crates/fs-ext/testdata/gen-fixtures.sh
```

The fscrypt fixture is the only entry in `gen-fixtures.sh` that requires
root and a kernel with fscrypt support; the other fixtures build under
the unprivileged path. If sudo, `losetup`, `e4crypt`, or `python3` are
missing the script prints a `==> Skipping ext4-fscrypt.img …` line and
returns 0 without producing the image.

The `.img` is committed to git so unit tests run without requiring the
fixture to be regenerated. Re-run the script only when the on-disk
layout intentionally changes.

## Geometry

| field         | value                                    |
| ------------- | ---------------------------------------- |
| size          | 8 MiB                                    |
| block size    | 4 KiB (mkfs default)                     |
| journal       | none (`^has_journal`)                    |
| inodes        | 256 (`-N 256`)                           |
| UUID          | `55555555-5555-5555-5555-555555555555`   |
| features      | `encrypt,casefold,filetype,extent,64bit,flex_bg,metadata_csum,stable_inodes,^has_journal` |
| encoding      | `utf8`                                   |

## Master keys

All four master keys are SHA-512 derivations of fixed ASCII labels,
truncated to 64 bytes (the kernel `FSCRYPT_MAX_KEY_SIZE`):

| symbol           | derivation                                               |
| ---------------- | -------------------------------------------------------- |
| `MK_V1`          | `sha512("tracium-fscrypt-v1-fixture")[:64]`              |
| `MK_V1_ADIANTUM` | `sha512("tracium-fscrypt-v1-adiantum-fixture")[:64]`     |
| `MK_V2`          | `sha512("tracium-fscrypt-v2-fixture")[:64]`              |
| `MK_V2_CF`       | `sha512("tracium-fscrypt-v2-casefold-fixture")[:64]`     |
| `MK_V2_ADIANTUM` | `sha512("tracium-fscrypt-v2-adiantum-fixture")[:64]`     |
| `MK_V2_IV64`     | `sha512("tracium-fscrypt-v2-iv-ino-lblk-64-fixture")[:64]` |
| `MK_V2_IV32`     | `sha512("tracium-fscrypt-v2-iv-ino-lblk-32-fixture")[:64]` |
| `MK_V2_DUS512`   | `sha512("tracium-fscrypt-v2-dus512-fixture")[:64]` |
| `MK_V2_DIRECT_KEY` | `sha512("tracium-fscrypt-v2-direct-key-fixture")[:64]` |
| `MK_V2_AES128`   | `sha512("tracium-fscrypt-v2-aes128-fixture")[:64]` |
| `MK_V2_SM4`      | `sha512("tracium-fscrypt-v2-sm4-fixture")[:64]` |
| `MK_V2_HCTR2`    | `sha512("tracium-fscrypt-v2-hctr2-fixture")[:64]` |

The v1 master-key descriptors are operator-chosen: `v1_dir` uses
`0xAA` × 8 and `v1_adiantum_dir` uses `0xBB` × 8. The v2 master-key
identifier is computed by the kernel via HKDF-SHA512 at key-add time;
the script verifies the kernel's identifier matches the Python-side
computation, which mirrors `crate::fscrypt::kdf_v2::key_identifier`.

## Tree layout

| path                        | content / target  |
| --------------------------- | ----------------- |
| `v1_dir/`                   | v1 policy, AES-256-XTS / AES-256-CTS, PAD_16 |
| `v1_dir/hello.txt`          | `"v1 hello\n"`    |
| `v1_dir/subdir/`            | encrypted child directory |
| `v1_dir/subdir/nested.txt`  | `"v1 nested\n"`   |
| `v1_adiantum_dir/`          | v1 policy, Adiantum / Adiantum, PAD_16 |
| `v1_adiantum_dir/hello.txt` | `"v1 adiantum hello\n"`                |
| `v1_adiantum_dir/slink`     | symlink → `hello.txt`                  |
| `v2_dir/`                   | v2 policy, AES-256-XTS / AES-256-CTS, PAD_16 |
| `v2_dir/hello.txt`          | `"v2 hello\n"`    |
| `v2_dir/subdir/`            | encrypted child directory |
| `v2_dir/subdir/nested.txt`  | `"v2 nested\n"`   |
| `v2_dir/slink`              | symlink → `hello.txt` |
| `v2_dir/long_nokey_sha256_test_X…X.bin` | 200-byte plaintext name (`"long_nokey_sha256_test_" + "X"*173 + ".bin"`); ciphertext > 149 B exercises the SHA-256 tail of the no-key encoder (#167) |
| `v2_cf_dir/`                | v2 policy + `EXT4_CASEFOLD_FL` (htree v6 / SipHash dirhash) |
| `v2_cf_dir/Hello.TXT`       | `"v2cf hello\n"`  |
| `v2_cf_dir/READ.ME`         | `"v2cf readme\n"` |
| `v2_adiantum_dir/`          | v2 policy, Adiantum / Adiantum, PAD_16 |
| `v2_adiantum_dir/hello.txt` | `"adiantum hello\n"`                   |
| `v2_adiantum_dir/slink`     | symlink → `hello.txt`                  |
| `v2_iv64_dir/`              | v2 policy, AES-256-XTS / AES-256-CTS, PAD_16 + IV_INO_LBLK_64 |
| `v2_iv64_dir/hello.txt`     | `"iv64 hello\n"`                       |
| `v2_iv64_dir/subdir/`       | encrypted child directory under the same policy |
| `v2_iv64_dir/subdir/nested.txt` | `"iv64 nested\n"`                  |
| `v2_iv64_dir/slink`         | symlink → `hello.txt`                  |
| `v2_iv32_dir/`              | v2 policy, AES-256-XTS / AES-256-CTS, PAD_16 + IV_INO_LBLK_32 |
| `v2_iv32_dir/hello.txt`     | `"iv32 hello\n"`                       |
| `v2_iv32_dir/subdir/`       | encrypted child directory under the same policy |
| `v2_iv32_dir/subdir/nested.txt` | `"iv32 nested\n"`                  |
| `v2_iv32_dir/slink`         | symlink → `hello.txt`                  |
| `v2_dus512_dir/`            | v2 policy, AES-256-XTS / AES-256-CTS, PAD_16, log2_data_unit_size = 9 (512 B) |
| `v2_dus512_dir/hello.txt`   | `"dus512 hello\n"`                     |
| `v2_dus512_dir/multi_unit.bin` | 4 KiB plaintext: 512 B of byte 0, then 1, … through 7 |
| `v2_direct_key_dir/`        | v2 policy, Adiantum / Adiantum, PAD_16 + DIRECT_KEY |
| `v2_direct_key_dir/hello.txt` | `"direct_key hello\n"`               |
| `v2_direct_key_dir/subdir/` | encrypted child directory under the same policy |
| `v2_direct_key_dir/subdir/nested.txt` | `"direct_key nested\n"`      |
| `v2_direct_key_dir/slink`   | symlink → `hello.txt`                  |
| `v2_aes128_dir/`            | v2 policy, AES-128-CBC-ESSIV / AES-128-CTS, PAD_16 |
| `v2_aes128_dir/hello.txt`   | `"aes128 hello\n"`                     |
| `v2_aes128_dir/subdir/`     | encrypted child directory under the same policy |
| `v2_aes128_dir/subdir/nested.txt` | `"aes128 nested\n"`              |
| `v2_aes128_dir/slink`       | symlink → `hello.txt`                  |
| `v2_sm4_dir/` (CONFIG_CRYPTO_SM4) | v2 policy, SM4-XTS / SM4-CBC-CTS, PAD_16 |
| `v2_sm4_dir/hello.txt`      | `"sm4 hello\n"`                        |
| `v2_sm4_dir/subdir/`        | encrypted child directory under the same policy |
| `v2_sm4_dir/subdir/nested.txt` | `"sm4 nested\n"`                    |
| `v2_sm4_dir/slink`          | symlink → `hello.txt`                  |
| `v2_hctr2_dir/` (kernel ≥ 6.0) | v2 policy, AES-256-XTS / AES-256-HCTR2, PAD_16 |
| `v2_hctr2_dir/hello.txt`    | `"hctr2 hello\n"`                      |
| `v2_hctr2_dir/subdir/`      | encrypted child directory under the same policy |
| `v2_hctr2_dir/subdir/nested.txt` | `"hctr2 nested\n"`                |
| `v2_hctr2_dir/slink`        | symlink → `hello.txt`                  |

## Policy parameters

| directory          | contents          | filenames         | flags                          |
|--------------------|-------------------|-------------------|--------------------------------|
| `v1_dir/`          | AES_256_XTS       | AES_256_CTS       | PAD_16                         |
| `v1_adiantum_dir/` | Adiantum          | Adiantum          | PAD_16                         |
| `v2_dir/`          | AES_256_XTS       | AES_256_CTS       | PAD_16                         |
| `v2_cf_dir/`       | AES_256_XTS       | AES_256_CTS       | PAD_16                         |
| `v2_adiantum_dir/` | Adiantum          | Adiantum          | PAD_16                         |
| `v2_iv64_dir/`     | AES_256_XTS       | AES_256_CTS       | PAD_16 \| IV_INO_LBLK_64       |
| `v2_iv32_dir/`     | AES_256_XTS       | AES_256_CTS       | PAD_16 \| IV_INO_LBLK_32       |
| `v2_dus512_dir/`   | AES_256_XTS       | AES_256_CTS       | PAD_16 (+ log2_data_unit_size = 9) |
| `v2_direct_key_dir/` | Adiantum        | Adiantum          | PAD_16 \| DIRECT_KEY           |
| `v2_aes128_dir/`   | AES_128_CBC       | AES_128_CTS       | PAD_16                         |
| `v2_sm4_dir/`      | SM4_XTS           | SM4_CTS           | PAD_16                         |
| `v2_hctr2_dir/`    | AES_256_XTS       | AES_256_HCTR2     | PAD_16                         |

Apart from `v2_dus512_dir/` (which uses `log2_data_unit_size = 9`),
every `v2_*` directory carries `log2_data_unit_size = 0` (filesystem
block size). `crate::fscrypt` accepts both 0 and any value in
`[SECTOR_SHIFT (9), log2(fs_block_size)]`; sub-block units require
kernel ≥ 6.7 to generate.
