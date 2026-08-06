use std::fs;
use std::path::Path;

use fs_ntfs::UsnRecord;
use fs_ntfs::types::NtfsPosition;

/// Regression harnesses for libFuzzer crashes found in `fuzz_ntfs_usn_record`.
///
/// Each test loads a specific crashing input from disk and exercises the same
/// record-parsing path as the `fuzz_ntfs_usn_record` fuzz target.
fn run_fuzz_ntfs_usn_record_artifact(file_name: &str) {
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crashes/libfuzzer/fuzz_ntfs_usn_record")
        .join(file_name);

    if !artifact_path.exists() {
        panic!("Artifact not found at {}.", artifact_path.display());
    }

    let data =
        fs::read(&artifact_path).expect("failed to read fuzz artifact for fuzz_ntfs_usn_record");

    let pos = NtfsPosition::none();

    if let Ok(record) = UsnRecord::from_bytes(&data, pos) {
        // Exercise all accessors.
        let _ = record.record_length();
        let _ = record.major_version();
        let _ = record.minor_version();
        let _ = record.file_reference();
        let _ = record.parent_reference();
        let _ = record.usn();
        let _ = record.timestamp();
        let _ = record.reason();
        let _ = record.source_info();
        let _ = record.security_id();
        let _ = record.file_attributes();
        let _ = record.file_name_length();
        let _ = record.file_name_offset();
        let _ = record.position();

        // Exercise the file name (UTF-16 string).
        let name = record.file_name();
        let _ = name.to_string();

        // Exercise convenience predicates.
        let _ = record.is_create();
        let _ = record.is_delete();
        let _ = record.is_rename();
        let _ = record.is_close();
    }
}

#[test]
fn fuzz_ntfs_usn_record_crash_08100fbdc62241a1dfc65402269d525cb64649c6() {
    run_fuzz_ntfs_usn_record_artifact("crash-08100fbdc62241a1dfc65402269d525cb64649c6");
}

#[test]
fn fuzz_ntfs_usn_record_crash_0bda155e470099ecf9ce11f787bcfef74e4aa1fa() {
    run_fuzz_ntfs_usn_record_artifact("crash-0bda155e470099ecf9ce11f787bcfef74e4aa1fa");
}

#[test]
fn fuzz_ntfs_usn_record_crash_1c380f2f43def7725c8eb0598c088db17c3ee554() {
    run_fuzz_ntfs_usn_record_artifact("crash-1c380f2f43def7725c8eb0598c088db17c3ee554");
}

#[test]
fn fuzz_ntfs_usn_record_crash_3523b01ffaba1f87f70827563be7398c7abb3f2b() {
    run_fuzz_ntfs_usn_record_artifact("crash-3523b01ffaba1f87f70827563be7398c7abb3f2b");
}

#[test]
fn fuzz_ntfs_usn_record_crash_53f526e926cf1f1210309d8a2f5df9cc25f66305() {
    run_fuzz_ntfs_usn_record_artifact("crash-53f526e926cf1f1210309d8a2f5df9cc25f66305");
}

#[test]
fn fuzz_ntfs_usn_record_crash_567fa5f73547f3b11fce4dd6e26010dd5d00266d() {
    run_fuzz_ntfs_usn_record_artifact("crash-567fa5f73547f3b11fce4dd6e26010dd5d00266d");
}

#[test]
fn fuzz_ntfs_usn_record_crash_591bc0026783d8a26b4d3c154627e81c923cd478() {
    run_fuzz_ntfs_usn_record_artifact("crash-591bc0026783d8a26b4d3c154627e81c923cd478");
}

#[test]
fn fuzz_ntfs_usn_record_crash_66a62b6a3a8e2f352b25756468d919a60a13cf4e() {
    run_fuzz_ntfs_usn_record_artifact("crash-66a62b6a3a8e2f352b25756468d919a60a13cf4e");
}

#[test]
fn fuzz_ntfs_usn_record_crash_80130fe408eef950828bc6b4f0adf836df6f088c() {
    run_fuzz_ntfs_usn_record_artifact("crash-80130fe408eef950828bc6b4f0adf836df6f088c");
}

#[test]
fn fuzz_ntfs_usn_record_crash_8bc379f15bb7b300bf9936c5874d46c492f9eb2f() {
    run_fuzz_ntfs_usn_record_artifact("crash-8bc379f15bb7b300bf9936c5874d46c492f9eb2f");
}

#[test]
fn fuzz_ntfs_usn_record_crash_8eefac81306c47b4d526306c08d7fbfb89e125e6() {
    run_fuzz_ntfs_usn_record_artifact("crash-8eefac81306c47b4d526306c08d7fbfb89e125e6");
}

#[test]
fn fuzz_ntfs_usn_record_crash_9c2d0f9293ac162ac673c680eb9fcfcecb7dc84f() {
    run_fuzz_ntfs_usn_record_artifact("crash-9c2d0f9293ac162ac673c680eb9fcfcecb7dc84f");
}

#[test]
fn fuzz_ntfs_usn_record_crash_a337737da969e149392c04aa0be1e377a32fed32() {
    run_fuzz_ntfs_usn_record_artifact("crash-a337737da969e149392c04aa0be1e377a32fed32");
}

#[test]
fn fuzz_ntfs_usn_record_crash_aa75720f731b1de982a37ffabcbe5ed6e2a46c57() {
    run_fuzz_ntfs_usn_record_artifact("crash-aa75720f731b1de982a37ffabcbe5ed6e2a46c57");
}

#[test]
fn fuzz_ntfs_usn_record_crash_aae4ddd2dd2e4a8a4b8a199dcf6a47cf9f319a54() {
    run_fuzz_ntfs_usn_record_artifact("crash-aae4ddd2dd2e4a8a4b8a199dcf6a47cf9f319a54");
}

#[test]
fn fuzz_ntfs_usn_record_crash_acb8ef12b05bda0a4549d3be6c6a4337e1513182() {
    run_fuzz_ntfs_usn_record_artifact("crash-acb8ef12b05bda0a4549d3be6c6a4337e1513182");
}

#[test]
fn fuzz_ntfs_usn_record_crash_adca1ccf9c10c0c64dc9948823c472e9ced5e435() {
    run_fuzz_ntfs_usn_record_artifact("crash-adca1ccf9c10c0c64dc9948823c472e9ced5e435");
}

#[test]
fn fuzz_ntfs_usn_record_crash_b830721730f6573a6dc1e6e315fab3db566c0134() {
    run_fuzz_ntfs_usn_record_artifact("crash-b830721730f6573a6dc1e6e315fab3db566c0134");
}

#[test]
fn fuzz_ntfs_usn_record_crash_d17d05b29f918a42b47a984704d75a9de25204b8() {
    run_fuzz_ntfs_usn_record_artifact("crash-d17d05b29f918a42b47a984704d75a9de25204b8");
}

#[test]
fn fuzz_ntfs_usn_record_crash_e4cc8284c417bb91297491bdfa40cc86934e08a2() {
    run_fuzz_ntfs_usn_record_artifact("crash-e4cc8284c417bb91297491bdfa40cc86934e08a2");
}

#[test]
fn fuzz_ntfs_usn_record_crash_e77e6796bd052a5178ef83aa0fb52d688faebd0a() {
    run_fuzz_ntfs_usn_record_artifact("crash-e77e6796bd052a5178ef83aa0fb52d688faebd0a");
}

#[test]
fn fuzz_ntfs_usn_record_crash_fc8359b0dc30cdbf8f14c3f553b6e5afe5eae411() {
    run_fuzz_ntfs_usn_record_artifact("crash-fc8359b0dc30cdbf8f14c3f553b6e5afe5eae411");
}
