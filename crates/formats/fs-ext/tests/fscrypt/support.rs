pub(crate) use fsmnt_testkit::Cursor;

pub(crate) use fs_common::FsTryIterator;
pub(crate) use fs_common::io::FsReadSeek;
pub(crate) use fs_common::traverse::{EntryKind, FsDirectory};
pub(crate) use fs_ext::{
    Ext, ExtError, FscryptKeyDescriptor, FscryptKeyUnwrapError, FscryptKeyUnwrapper,
    FscryptMasterKey,
};
pub(crate) use sha2::{Digest, Sha256, Sha512};

pub(crate) const IMAGE: &str = "testdata/ext4-fscrypt.img";

pub(crate) const V1_KEY_LABEL: &str = "tracium-fscrypt-v1-fixture";
pub(crate) const V1_ADIANTUM_KEY_LABEL: &str = "tracium-fscrypt-v1-adiantum-fixture";
pub(crate) const V2_KEY_LABEL: &str = "tracium-fscrypt-v2-fixture";
pub(crate) const V2_CF_KEY_LABEL: &str = "tracium-fscrypt-v2-casefold-fixture";
pub(crate) const V2_ADIANTUM_KEY_LABEL: &str = "tracium-fscrypt-v2-adiantum-fixture";
pub(crate) const V2_IV64_KEY_LABEL: &str = "tracium-fscrypt-v2-iv-ino-lblk-64-fixture";
pub(crate) const V2_IV32_KEY_LABEL: &str = "tracium-fscrypt-v2-iv-ino-lblk-32-fixture";
pub(crate) const V2_DUS512_KEY_LABEL: &str = "tracium-fscrypt-v2-dus512-fixture";
pub(crate) const V2_DIRECT_KEY_KEY_LABEL: &str = "tracium-fscrypt-v2-direct-key-fixture";
pub(crate) const V2_AES128_KEY_LABEL: &str = "tracium-fscrypt-v2-aes128-fixture";
pub(crate) const V2_SM4_KEY_LABEL: &str = "tracium-fscrypt-v2-sm4-fixture";
pub(crate) const V2_HCTR2_KEY_LABEL: &str = "tracium-fscrypt-v2-hctr2-fixture";

pub(crate) const V1_ADIANTUM_HELLO: &[u8] = b"v1 adiantum hello\n";
// Used by Tasks 19-22 Adiantum integration tests (fixture dir added in Task 16).
pub(crate) const V2_ADIANTUM_HELLO: &[u8] = b"adiantum hello\n";

pub(crate) const V2_IV64_HELLO: &[u8] = b"iv64 hello\n";
pub(crate) const V2_IV64_NESTED: &[u8] = b"iv64 nested\n";
pub(crate) const V2_IV32_HELLO: &[u8] = b"iv32 hello\n";
pub(crate) const V2_IV32_NESTED: &[u8] = b"iv32 nested\n";
pub(crate) const V2_DUS512_HELLO: &[u8] = b"dus512 hello\n";
pub(crate) const V2_DIRECT_KEY_HELLO: &[u8] = b"direct_key hello\n";
pub(crate) const V2_DIRECT_KEY_NESTED: &[u8] = b"direct_key nested\n";
pub(crate) const V2_AES128_HELLO: &[u8] = b"aes128 hello\n";
pub(crate) const V2_AES128_NESTED: &[u8] = b"aes128 nested\n";
pub(crate) const V2_SM4_HELLO: &[u8] = b"sm4 hello\n";
pub(crate) const V2_SM4_NESTED: &[u8] = b"sm4 nested\n";
pub(crate) const V2_HCTR2_HELLO: &[u8] = b"hctr2 hello\n";
pub(crate) const V2_HCTR2_NESTED: &[u8] = b"hctr2 nested\n";

pub(crate) const V1_DESCRIPTOR: [u8; 8] = [0xAA; 8];
pub(crate) const V1_ADIANTUM_DESCRIPTOR: [u8; 8] = [0xBB; 8];

pub(crate) const V1_HELLO: &[u8] = b"v1 hello\n";
pub(crate) const V1_NESTED: &[u8] = b"v1 nested\n";
pub(crate) const V2_HELLO: &[u8] = b"v2 hello\n";
pub(crate) const V2_NESTED: &[u8] = b"v2 nested\n";
pub(crate) const V2CF_HELLO: &[u8] = b"v2cf hello\n";
pub(crate) const V2CF_README: &[u8] = b"v2cf readme\n";

pub(crate) fn key_from_string(s: &str) -> FscryptMasterKey {
    let mut hasher = Sha512::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut k = [0u8; 64];
    k.copy_from_slice(&digest[..]);
    FscryptMasterKey::from_array(k)
}

pub(crate) fn fixture_bytes() -> Vec<u8> {
    fsmnt_testkit::read_required_fixture(
        env!("CARGO_MANIFEST_DIR"),
        IMAGE,
        "regenerate via `sudo bash crates/formats/fs-ext/testdata/gen-fixtures.sh`",
    )
}

pub(crate) fn open_with_keys() -> (Cursor<Vec<u8>>, Ext) {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");
    ext.add_fscrypt_v1_key(
        FscryptKeyDescriptor(V1_DESCRIPTOR),
        key_from_string(V1_KEY_LABEL),
    )
    .expect("v1 64-byte key passes validation");
    ext.add_fscrypt_v1_key(
        FscryptKeyDescriptor(V1_ADIANTUM_DESCRIPTOR),
        key_from_string(V1_ADIANTUM_KEY_LABEL),
    )
    .expect("v1 Adiantum 64-byte key passes validation");
    ext.add_fscrypt_v2_key(key_from_string(V2_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_CF_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_ADIANTUM_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_IV64_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_IV32_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_DUS512_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_DIRECT_KEY_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_AES128_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_SM4_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_HCTR2_KEY_LABEL));
    (cursor, ext)
}

/// Returns true when the fixture image carries `v2_sm4_dir/`. Older
/// kernels without `CONFIG_CRYPTO_SM4` skip the fixture directory at
/// gen time; tests must skip in lockstep.
///
/// Distinguishes "directory not present" (`NotFound`) from real
/// regressions (IO / parse / fscrypt errors) — only the former should
/// silently skip; everything else propagates so a broken SM4 path
/// fails the test instead of going unnoticed.
pub(crate) fn fixture_has_sm4_dir(cursor: &mut Cursor<Vec<u8>>, ext: &Ext) -> bool {
    let mut root = ext.root_directory();
    match root.lookup(cursor, b"v2_sm4_dir") {
        Ok(_) => true,
        Err(ExtError::NotFound) => false,
        Err(other) => panic!("v2_sm4_dir lookup failed unexpectedly: {other:?}"),
    }
}

/// Returns true when the fixture image carries `v2_hctr2_dir/`. Older
/// kernels (< 6.0) or kernels without `CONFIG_CRYPTO_HCTR2` skip the
/// fixture directory at gen time; tests must skip in lockstep.
///
/// Same NotFound-vs-real-error discrimination as `fixture_has_sm4_dir`
/// (Codex P2 in #163) so a regression in the HCTR2 path doesn't get
/// silently masked as "directory absent".
pub(crate) fn fixture_has_hctr2_dir(cursor: &mut Cursor<Vec<u8>>, ext: &Ext) -> bool {
    let mut root = ext.root_directory();
    match root.lookup(cursor, b"v2_hctr2_dir") {
        Ok(_) => true,
        Err(ExtError::NotFound) => false,
        Err(other) => panic!("v2_hctr2_dir lookup failed unexpectedly: {other:?}"),
    }
}

pub(crate) fn open_without_keys() -> (Cursor<Vec<u8>>, Ext) {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");
    (cursor, ext)
}

pub(crate) fn read_full_file(file: &mut fs_ext::ExtFile<'_>, fs: &mut Cursor<Vec<u8>>) -> Vec<u8> {
    let len = usize::try_from(<fs_ext::ExtFile<'_> as FsReadSeek<Cursor<Vec<u8>>>>::len(
        file,
    ))
    .expect("fixture file length fits usize");
    let mut buf = vec![0u8; len];
    file.read_exact(fs, &mut buf).expect("read encrypted file");
    buf
}
