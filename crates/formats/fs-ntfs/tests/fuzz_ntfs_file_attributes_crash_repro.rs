//! Regression tests for malformed file-attribute fuzz artifacts.

use std::io::Cursor;

use fsmnt_testkit::read_required_fixture;

/// Regression harnesses for libFuzzer crashes found in `fuzz_ntfs_file_attributes`.
///
/// Each test loads a specific crashing input from disk and exercises the same
/// attribute-iteration path as the `fuzz_ntfs_file_attributes` fuzz target so
/// you can debug it under `cargo test`.
fn run_fuzz_ntfs_file_attributes_artifact(file_name: &str) {
    // Ensure a full backtrace is printed if this test panics.
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let data = read_required_fixture(
        env!("CARGO_MANIFEST_DIR"),
        format!("../../crashes/libfuzzer/fuzz_ntfs_file_attributes/{file_name}"),
        "Regenerate the fuzz_ntfs_file_attributes corpus with cargo-fuzz.",
    );
    let mut cursor = Cursor::new(&data[..]);

    // Reproduce the fuzz target logic as closely as possible.
    let Ok(ntfs) = fs_ntfs::Ntfs::new(&mut cursor) else {
        return;
    };

    // Try to get the $MFT file (record 0)
    let Ok(mft_file) = ntfs.file(&mut cursor, 0) else {
        return;
    };

    // Iterate through all attributes using attributes_raw()
    let attrs = mft_file.attributes_raw();
    for attr_result in attrs {
        match attr_result {
            Ok(attr) => {
                // Access attribute properties
                let _ = attr.ty();
                let _ = attr.name();
                let _ = attr.is_resident();
                let _ = attr.value_length();

                // Try to get the attribute value
                if let Ok(value) = attr.value(&mut cursor) {
                    // Try to read some data from the value
                    use fs_common::io::FsReadSeek;
                    let mut buf = [0u8; 64];
                    let mut value = value;
                    let _ = value.read(&mut cursor, &mut buf);
                }
            }
            Err(_) => break,
        }
    }

    // Also try to get standard info and file name
    let _ = mft_file.info();
    let _ = mft_file.name(&mut cursor, None, None);
}

#[test]
fn fuzz_ntfs_file_attributes_crash_c3c71914eb5ea720fb0d04bbeea95191d08b7826() {
    run_fuzz_ntfs_file_attributes_artifact("crash-c3c71914eb5ea720fb0d04bbeea95191d08b7826");
}
