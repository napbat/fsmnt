//! Public-API coverage for mounting an fscrypt (Android FBE) volume: what
//! a mount shows without the master keys, what changes once they are
//! supplied, and what the mount says it is asking for either way.
//!
//! Driven through `fs-ext`'s tracked `ext4-fscrypt.img`, whose twelve
//! encrypted directories carry known keys — the master keys are SHA-512 of
//! fixed labels, so the test recomputes them exactly as the fixture
//! generator did rather than storing key bytes of its own.

use fsmnt::device::FscryptKeySpec;
use fsmnt::{FsEntry, ImageOpenOptions, TargetFilesystem, drivers, open_image_with_options};
use sha2::{Digest, Sha512};

/// The v1 master-key descriptor the fixture's `v1_dir` policy names.
const V1_DESCRIPTOR: [u8; 8] = [0xAA; 8];

/// The census line the fixture's plain v2 directory produces: the only
/// policy in the image that is v2 + AES-256-XTS/AES-256-CTS with no extra
/// flags, so it identifies `v2_dir` on its own.
const V2_DIR_POLICY: &str = "v2, AES-256-XTS/AES-256-CTS, PAD_16";

/// Master key for a fixture label: `sha512(label)[..64]`, as
/// `testdata/gen-fixtures.sh` derived it.
fn master_key(label: &str) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(label.as_bytes());
    hasher.finalize()[..64].to_vec()
}

/// Open the fscrypt fixture with `keys` registered.
///
/// The image is tracked, so unlike the generated fixtures this never skips.
fn mount(keys: Vec<FscryptKeySpec>) -> Box<dyn TargetFilesystem> {
    let path = fsmnt_testkit::fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        "crates/formats/fs-ext/testdata/ext4-fscrypt.img",
    );
    let options = ImageOpenOptions::new().with_filesystem_options(
        fsmnt::device::FilesystemOpenOptions::new().with_fscrypt_keys(keys),
    );
    open_image_with_options(&path, &drivers::default_registry(), options)
        .expect("the tracked ext4-fscrypt.img opens as an ext volume")
        .filesystem
}

/// Entry names of `path`, sorted.
fn names(fs: &mut dyn TargetFilesystem, path: &str) -> Vec<String> {
    let mut listed: Vec<String> = fs
        .read_dir(path)
        .unwrap_or_else(|error| panic!("listing {path}: {error}"))
        .iter()
        .map(|entry: &FsEntry| entry.name.clone())
        .collect();
    listed.sort();
    listed
}

/// The census lines, i.e. every notice naming a key.
fn census(fs: &dyn TargetFilesystem) -> Vec<String> {
    fs.notices()
        .into_iter()
        .filter(|notice| notice.starts_with("fscrypt key "))
        .collect()
}

#[test]
fn without_keys_names_are_the_kernels_no_key_form_and_contents_are_refused() {
    let mut fs = mount(Vec::new());

    // The kernel's no-key presentation is base64url of the ciphertext, so
    // the entries are ASCII but none of them is the plaintext name.
    let listed = names(fs.as_mut(), "/v2_dir");
    assert!(
        !listed.contains(&"hello.txt".to_string()),
        "a directory with no key must not present plaintext names: {listed:?}"
    );
    assert!(
        listed.iter().all(|name| {
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }),
        "no-key names are base64url and nothing else: {listed:?}"
    );
    assert!(
        !listed.is_empty(),
        "the directory still lists; only its names are ciphertext"
    );

    // Reading through an encrypted directory says which key is missing and
    // how to hand it over.
    let error = fs
        .read("/v2_dir/hello.txt")
        .expect_err("an encrypted file cannot be read without its master key");
    let message = error.to_string();
    assert!(message.contains("fscrypt"), "{message}");
    assert!(message.contains("--fscrypt-key"), "{message}");
    assert!(
        message.contains("key ") && message.contains("not registered"),
        "the message must name the key reference: {message}"
    );

    // And the mount says so up front, before anything is read.
    let notices = fs.notices();
    assert!(
        notices
            .iter()
            .any(|notice| notice.contains("no keys registered")),
        "{notices:?}"
    );
    let lines = census(fs.as_ref());
    assert!(
        lines.iter().any(|line| line.contains(V2_DIR_POLICY)
            && line.contains("NOT registered")
            && line.contains("/v2_dir")),
        "the census must name v2_dir's key as missing: {lines:?}"
    );
    assert!(
        lines.iter().all(|line| line.contains("NOT registered")),
        "with no keys, nothing can be registered: {lines:?}"
    );
}

#[test]
fn a_v2_key_unlocks_its_directorys_names_and_contents() {
    let key = master_key("tracium-fscrypt-v2-fixture");
    let mut fs = mount(vec![FscryptKeySpec::v2(key)]);

    let listed = names(fs.as_mut(), "/v2_dir");
    assert!(
        listed.contains(&"hello.txt".to_string()) && listed.contains(&"subdir".to_string()),
        "the registered key makes the names plaintext: {listed:?}"
    );

    assert_eq!(
        fs.read("/v2_dir/hello.txt").expect("v2 hello"),
        b"v2 hello\n"
    );
    assert_eq!(
        fs.read("/v2_dir/subdir/nested.txt").expect("v2 nested"),
        b"v2 nested\n"
    );

    // Exactly one of the fixture's policies is covered: the identifier a v2
    // key answers to is derived from the key, so registering one key
    // unlocks one key's worth of directories and no more.
    let lines = census(fs.as_ref());
    let registered: Vec<&String> = lines
        .iter()
        .filter(|line| line.ends_with("— registered") || line.contains("— registered;"))
        .collect();
    assert_eq!(
        registered.len(),
        1,
        "one key registered, one policy covered: {lines:?}"
    );
    assert!(
        registered[0].contains(V2_DIR_POLICY) && registered[0].contains("/v2_dir"),
        "{registered:?}"
    );
    assert!(
        registered[0].contains("fscrypt key identifier "),
        "a v2 policy names its key by the derived identifier: {registered:?}"
    );
}

#[test]
fn a_v1_key_needs_its_descriptor_and_then_reads_the_same_way() {
    let key = master_key("tracium-fscrypt-v1-fixture");
    let mut fs = mount(vec![FscryptKeySpec::v1(V1_DESCRIPTOR, key)]);

    let listed = names(fs.as_mut(), "/v1_dir");
    assert!(
        listed.contains(&"hello.txt".to_string()) && listed.contains(&"subdir".to_string()),
        "{listed:?}"
    );
    assert_eq!(
        fs.read("/v1_dir/hello.txt").expect("v1 hello"),
        b"v1 hello\n"
    );
    assert_eq!(
        fs.read("/v1_dir/subdir/nested.txt").expect("v1 nested"),
        b"v1 nested\n"
    );

    let lines = census(fs.as_ref());
    assert!(
        lines.iter().any(|line| {
            line.starts_with("fscrypt key descriptor aaaaaaaaaaaaaaaa: v1, ")
                && line.contains("— registered")
                && line.contains("/v1_dir")
        }),
        "a v1 policy names its key by the descriptor the operator chose: {lines:?}"
    );
}

#[test]
fn the_same_spec_grammar_the_command_line_takes_registers_a_key() {
    // What an operator actually types, end to end: the CLI's value parser
    // and the driver's registration are the same two steps this exercises.
    let hex: String =
        master_key("tracium-fscrypt-v2-fixture")
            .iter()
            .fold(String::new(), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            });
    let spec: FscryptKeySpec = hex.parse().expect("64 bytes of hex is a v2 key");
    let mut fs = mount(vec![spec]);
    assert_eq!(
        fs.read("/v2_dir/hello.txt").expect("v2 hello"),
        b"v2 hello\n"
    );
}

#[test]
fn a_key_that_fscrypt_cannot_use_is_refused_by_position_rather_than_ignored() {
    // A 32-byte v1 key parses fine as a spec — v1 key derivation is what
    // rejects it, at registration, before any read pretends to work.
    let path = fsmnt_testkit::fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        "crates/formats/fs-ext/testdata/ext4-fscrypt.img",
    );
    let options = ImageOpenOptions::new().with_filesystem_options(
        fsmnt::device::FilesystemOpenOptions::new().with_fscrypt_keys(vec![
            FscryptKeySpec::v2(vec![0x11; 32]),
            FscryptKeySpec::v1(V1_DESCRIPTOR, vec![0x22; 32]),
        ]),
    );
    let error = open_image_with_options(&path, &drivers::default_registry(), options)
        .err()
        .expect("a v1 key of 32 bytes cannot be registered");
    let message = error.to_string();
    assert!(message.contains("fscrypt key #2"), "{message}");
    assert!(
        message.contains("v1 master keys must be at least 64 bytes"),
        "{message}"
    );
}

#[test]
fn the_optional_cipher_directories_are_reported_when_the_fixture_has_them() {
    // SM4 and HCTR2 need kernel modules the fixture generator may not have
    // had, so the directories are optional — but when they are there the
    // census must name their keys like any other.
    let mut fs = mount(Vec::new());
    for (directory, policy) in [
        ("v2_sm4_dir", "v2, SM4-XTS/SM4-CTS, PAD_16"),
        ("v2_hctr2_dir", "v2, AES-256-XTS/AES-256-HCTR2, PAD_16"),
    ] {
        if !fs.try_exists(&format!("/{directory}")).unwrap_or(false) {
            eprintln!("skipping: {directory} absent from the fixture");
            continue;
        }
        let lines = census(fs.as_ref());
        assert!(
            lines
                .iter()
                .any(|line| line.contains(policy) && line.contains(directory)),
            "{directory} is present but not in the census: {lines:?}"
        );
    }
}
