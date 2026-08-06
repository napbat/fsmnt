use std::fs;
use std::path::Path;

use fs_common::iter::FsTryIterator;
use fs_ntfs::structured_values::NtfsAttributeList;
use fs_ntfs::types::NtfsPosition;

/// Regression harness for libFuzzer timeouts found in `fuzz_ntfs_attribute_list`.
///
/// Each test loads a specific crashing input and exercises the same
/// attribute-list iteration as the fuzz target.
fn run_fuzz_ntfs_attribute_list_artifact(file_name: &str) {
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crashes/libfuzzer/fuzz_ntfs_attribute_list")
        .join(file_name);

    if !artifact_path.exists() {
        panic!("Artifact not found at {}.", artifact_path.display());
    }

    let data = fs::read(&artifact_path)
        .expect("failed to read fuzz artifact for fuzz_ntfs_attribute_list");

    let pos = NtfsPosition::none();

    let attr_list: NtfsAttributeList<'_, '_> = NtfsAttributeList::Resident(&data, pos);
    let mut entries = attr_list.entries();
    let mut dummy = std::io::Cursor::new(Vec::<u8>::new());

    // Limit iterations to detect infinite loops (the timeout had no bound).
    let mut count = 0u32;
    while let Some(entry) = entries.try_next(&mut dummy).unwrap_or(None) {
        let _ = entry.ty();
        let _ = entry.instance();
        let _ = entry.list_entry_length();
        let _ = entry.lowest_vcn();
        let _ = entry.name();
        let _ = entry.name_length();
        let _ = entry.position();
        let _ = entry.base_file_reference();
        count += 1;
        if count > 1000 {
            panic!(
                "Infinite loop detected: iterated {} times on a {}-byte input",
                count,
                data.len()
            );
        }
    }
}

#[test]
fn fuzz_ntfs_attribute_list_timeout_adc83b19e793491b1c6ea0fd8b46cd9f32e592fc() {
    run_fuzz_ntfs_attribute_list_artifact("timeout-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc");
}
