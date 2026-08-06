use super::support::*;

// === Wrapped-key path (#156) =============================================

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Synthetic unwrap stub: the "wrapped" form is the master-key bytes
/// XOR'd against `pad`, and `unwrap_key` reverses the XOR. Real
/// operators bind to a TEE adapter; the tests just need the plumbing
/// to work end-to-end against a real fixture-derived key.
struct XorUnwrapper {
    pad: u8,
}

impl FscryptKeyUnwrapper for XorUnwrapper {
    fn unwrap_key(
        &self,
        wrapped: &[u8],
    ) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        let unwrapped: Vec<u8> = wrapped.iter().map(|b| b ^ self.pad).collect();
        FscryptMasterKey::from_bytes(&unwrapped)
            .map_err(|e| FscryptKeyUnwrapError::new(format!("{e:?}")))
    }
}

/// Counts unwrap calls so a test can pin the OnceCell-backed cache.
/// `Arc<AtomicUsize>` satisfies the trait's `Send + Sync` bounds.
struct CountingUnwrapper {
    inner: XorUnwrapper,
    calls: Arc<AtomicUsize>,
}

impl FscryptKeyUnwrapper for CountingUnwrapper {
    fn unwrap_key(
        &self,
        wrapped: &[u8],
    ) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.unwrap_key(wrapped)
    }
}

/// Failing unwrap stub for negative tests.
struct FailingUnwrapper;
impl FscryptKeyUnwrapper for FailingUnwrapper {
    fn unwrap_key(&self, _: &[u8]) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        Err(FscryptKeyUnwrapError::new("simulated TEE failure"))
    }
}

fn v2_identifier_for(label: &str) -> fs_ext::FscryptKeyIdentifier {
    // Mirror the kernel's HKDF-SHA512 identifier derivation by going
    // through `add_fscrypt_v2_key` once on a throwaway Ext, then
    // extracting the returned identifier. Avoids re-implementing the
    // KDF in the test helper.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();
    ext.add_fscrypt_v2_key(key_from_string(label))
}

fn xor_blob(key: &FscryptMasterKey, pad: u8) -> Vec<u8> {
    key.as_bytes().iter().map(|b| b ^ pad).collect()
}

#[test]
fn wrapped_key_unwrap_callback_decrypts_v2_dir() {
    // End-to-end plumbing: register the v2_dir master key via the
    // wrapped-key path (XOR pad), then confirm v2_dir/hello.txt
    // decrypts byte-for-byte. Pins that the lazy unwrap path produces
    // the same plaintext as the raw-key path.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw = key_from_string(V2_KEY_LABEL);
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    let wrapped = xor_blob(&raw, 0x55);
    ext.add_fscrypt_v2_wrapped_key(identifier, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_dir/hello.txt with wrapped key");
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2 hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_HELLO);
}

#[test]
fn wrapped_key_unwrap_failure_surfaces_as_unwrap_failed_error() {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    // Register a wrapped entry under v2_dir's identifier with a
    // FailingUnwrapper. The first inode lookup against the v2_dir
    // policy must surface FscryptKeyUnwrapFailed (NOT MissingFscryptKey,
    // NOT garbage), with the registered identifier in the error.
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    ext.add_fscrypt_v2_wrapped_key(identifier, vec![0u8; 64], Box::new(FailingUnwrapper));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("FailingUnwrapper must surface as Err, not silent garbage");
    match err {
        ExtError::FscryptKeyUnwrapFailed {
            policy_kind,
            key_ref,
            reason,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32);
            assert!(
                reason.contains("simulated TEE failure"),
                "reason = {reason}"
            );
        }
        other => panic!("expected FscryptKeyUnwrapFailed, got {other:?}"),
    }
}

#[test]
fn wrapped_key_identifier_mismatch_surfaces_as_unwrap_failed_error() {
    // Operator misconfiguration: wrapped blob unwraps to KEY_A but the
    // operator registered it under KEY_B's identifier. The keystore's
    // defensive identifier-verification check must surface
    // FscryptKeyUnwrapFailed rather than caching the wrong key.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw_v2 = key_from_string(V2_KEY_LABEL);
    let wrong_id = v2_identifier_for(V2_CF_KEY_LABEL); // belongs to a different key
    let wrapped = xor_blob(&raw_v2, 0x55);
    // Crucially: register under wrong_id so the lookup-against-wrong_id
    // path triggers the verification check on first unwrap.
    ext.add_fscrypt_v2_wrapped_key(wrong_id, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

    let mut root = ext.root_directory();
    let v2_cf_dir = root
        .lookup(&mut cursor, b"v2_cf_dir")
        .expect("lookup v2_cf_dir");
    let mut dir = ext.directory_at(v2_cf_dir.inode_number);
    let err = dir
        .lookup(&mut cursor, b"Hello.TXT")
        .expect_err("identifier mismatch must surface as Err");
    match err {
        ExtError::FscryptKeyUnwrapFailed { reason, .. } => {
            assert!(
                reason.contains("does not match registered"),
                "reason = {reason}"
            );
        }
        other => panic!("expected FscryptKeyUnwrapFailed, got {other:?}"),
    }
}

#[test]
fn wrapped_key_unwrap_callback_invoked_only_once_across_lookups() {
    // OnceCell cache: the unwrap callback runs exactly once for many
    // lookups against the same identifier. Multiple file decrypts
    // inside the same directory should all reuse the cached key.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw = key_from_string(V2_KEY_LABEL);
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    let wrapped = xor_blob(&raw, 0x55);
    let counter = Arc::new(AtomicUsize::new(0));
    let unwrapper = CountingUnwrapper {
        inner: XorUnwrapper { pad: 0x55 },
        calls: Arc::clone(&counter),
    };
    ext.add_fscrypt_v2_wrapped_key(identifier, wrapped, Box::new(unwrapper));

    // Two distinct lookups under the same v2 identifier:
    //   v2_dir/hello.txt  (regular file)
    //   v2_dir/subdir/nested.txt  (regular file under encrypted subdir)
    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").unwrap();
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir.lookup(&mut cursor, b"hello.txt").unwrap();
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    let _ = read_full_file(&mut file, &mut cursor);

    let subdir = dir.lookup(&mut cursor, b"subdir").unwrap();
    let mut sub = ext.directory_at(subdir.inode_number);
    let nested = sub.lookup(&mut cursor, b"nested.txt").unwrap();
    let inode = ext.inode(&mut cursor, nested.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    let _ = read_full_file(&mut file, &mut cursor);

    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "unwrap callback must be invoked exactly once across lookups"
    );
}

#[test]
fn raw_key_path_still_works_alongside_wrapped_keys() {
    // Acceptance criterion: "Existing raw-key path still works
    // unchanged." Register raw + wrapped keys side by side and confirm
    // both decrypt their respective fixture directories.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    // v2_dir via the raw path.
    ext.add_fscrypt_v2_key(key_from_string(V2_KEY_LABEL));
    // v2_cf_dir via the wrapped path.
    let raw_cf = key_from_string(V2_CF_KEY_LABEL);
    let id_cf = v2_identifier_for(V2_CF_KEY_LABEL);
    let wrapped_cf = xor_blob(&raw_cf, 0x33);
    ext.add_fscrypt_v2_wrapped_key(id_cf, wrapped_cf, Box::new(XorUnwrapper { pad: 0x33 }));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").unwrap();
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir.lookup(&mut cursor, b"hello.txt").unwrap();
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    assert_eq!(read_full_file(&mut file, &mut cursor), V2_HELLO);

    let v2_cf = root.lookup(&mut cursor, b"v2_cf_dir").unwrap();
    let mut cf = ext.directory_at(v2_cf.inode_number);
    let h = cf.lookup(&mut cursor, b"Hello.TXT").unwrap();
    let inode = ext.inode(&mut cursor, h.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    assert_eq!(read_full_file(&mut file, &mut cursor), V2CF_HELLO);
}
