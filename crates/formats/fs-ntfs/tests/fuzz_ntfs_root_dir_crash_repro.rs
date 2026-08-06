use fs_common::iter::FsTryIterator;
use std::fs;
use std::io::Cursor;
use std::path::Path;

/// Regression harnesses for libFuzzer crashes found in `fuzz_ntfs_root_dir`.
///
/// Each test loads a specific crashing input from disk and exercises the same
/// root-directory traversal path as the `fuzz_ntfs_root_dir` fuzz target so you
/// can debug it under `cargo test`.
fn run_fuzz_ntfs_root_dir_artifact(file_name: &str) {
    // Ensure a full backtrace is printed if this test panics.
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crashes/libfuzzer/fuzz_ntfs_root_dir")
        .join(file_name);

    if !artifact_path.exists() {
        panic!("Artifact not found at {}.", artifact_path.display());
    }

    let data =
        fs::read(&artifact_path).expect("failed to read fuzz artifact for fuzz_ntfs_root_dir");
    let mut cursor = Cursor::new(&data[..]);

    // Reproduce the fuzz target logic as closely as possible.
    let Ok(mut ntfs) = fs_ntfs::Ntfs::new(&mut cursor) else {
        return;
    };

    // Best-effort upcase table read (may legitimately fail).
    let _ = ntfs.read_upcase_table(&mut cursor);

    // Root directory lookup.
    let Ok(root_dir) = ntfs.root_directory(&mut cursor) else {
        return;
    };

    // Directory index lookup.
    let Ok(index) = root_dir.directory_index(&mut cursor) else {
        return;
    };

    // Iterate entries and touch file name data, mirroring the fuzz target.
    let mut iter = index.entries();
    while let Some(entry) = iter.try_next(&mut cursor).unwrap_or(None) {
        if let Some(Ok(file_name)) = entry.key() {
            let _ = file_name.name();
            let _ = file_name.namespace();
        }
    }
}

#[test]
fn fuzz_ntfs_root_dir_crash_6b0417b23c543adfc350eb35a4d89b2349e1144c() {
    run_fuzz_ntfs_root_dir_artifact("crash-6b0417b23c543adfc350eb35a4d89b2349e1144c");
}

#[test]
fn fuzz_ntfs_root_dir_crash_0c474fa24e9abbd4206bd4e0e758e3d91fc25eba() {
    run_fuzz_ntfs_root_dir_artifact("crash-0c474fa24e9abbd4206bd4e0e758e3d91fc25eba");
}

#[test]
fn fuzz_ntfs_root_dir_crash_b9e16432933964040225a252931a8cba1f221e51() {
    run_fuzz_ntfs_root_dir_artifact("crash-b9e16432933964040225a252931a8cba1f221e51");
}

// OOM regression tests — these inputs caused out-of-memory during index traversal.
// After fixes, they should complete (returning errors) without unbounded allocation.

#[test]
fn fuzz_ntfs_root_dir_oom_0132b97f85f0966e2d33454886476684dd119d24() {
    run_fuzz_ntfs_root_dir_artifact("oom-0132b97f85f0966e2d33454886476684dd119d24");
}

#[test]
fn fuzz_ntfs_root_dir_oom_049a9c690cf672bbc7fe36d43f3fc4992c5922c2() {
    run_fuzz_ntfs_root_dir_artifact("oom-049a9c690cf672bbc7fe36d43f3fc4992c5922c2");
}

#[test]
fn fuzz_ntfs_root_dir_oom_0b42777dc673badc3bc71d5ac272d3f0be159263() {
    run_fuzz_ntfs_root_dir_artifact("oom-0b42777dc673badc3bc71d5ac272d3f0be159263");
}

#[test]
fn fuzz_ntfs_root_dir_oom_13f059b5f7da3f31d6d1771d23965304f5ee335e() {
    run_fuzz_ntfs_root_dir_artifact("oom-13f059b5f7da3f31d6d1771d23965304f5ee335e");
}

#[test]
fn fuzz_ntfs_root_dir_oom_1ecdc5c670cc3ef635b8a02bd1254b670febaeab() {
    run_fuzz_ntfs_root_dir_artifact("oom-1ecdc5c670cc3ef635b8a02bd1254b670febaeab");
}

#[test]
fn fuzz_ntfs_root_dir_oom_22cb9a17383cced10eedad51ef5b9bac2fb7dd97() {
    run_fuzz_ntfs_root_dir_artifact("oom-22cb9a17383cced10eedad51ef5b9bac2fb7dd97");
}

#[test]
fn fuzz_ntfs_root_dir_oom_2904f01bf4a18e99d2f81b36bf0b0e2ace1375e7() {
    run_fuzz_ntfs_root_dir_artifact("oom-2904f01bf4a18e99d2f81b36bf0b0e2ace1375e7");
}

#[test]
fn fuzz_ntfs_root_dir_oom_42be500f5e3e365b1c35eaaf2d529e3b3de48b32() {
    run_fuzz_ntfs_root_dir_artifact("oom-42be500f5e3e365b1c35eaaf2d529e3b3de48b32");
}

#[test]
fn fuzz_ntfs_root_dir_oom_431d05d545a58454c8b0b6c78d53ddcb29a4c3a2() {
    run_fuzz_ntfs_root_dir_artifact("oom-431d05d545a58454c8b0b6c78d53ddcb29a4c3a2");
}

#[test]
fn fuzz_ntfs_root_dir_oom_466753a9f0e07d5adccbd7ad0bb0bd9435c4a9ba() {
    run_fuzz_ntfs_root_dir_artifact("oom-466753a9f0e07d5adccbd7ad0bb0bd9435c4a9ba");
}

#[test]
fn fuzz_ntfs_root_dir_oom_5ba78951313d07605e7a8754800f0e3377a8ee17() {
    run_fuzz_ntfs_root_dir_artifact("oom-5ba78951313d07605e7a8754800f0e3377a8ee17");
}

#[test]
fn fuzz_ntfs_root_dir_oom_7c22e9ea1ae97799ae93ebe03d63460ba278e680() {
    run_fuzz_ntfs_root_dir_artifact("oom-7c22e9ea1ae97799ae93ebe03d63460ba278e680");
}

#[test]
fn fuzz_ntfs_root_dir_oom_83b33873e7c61599e3e23c85b69d3216d167f0e3() {
    run_fuzz_ntfs_root_dir_artifact("oom-83b33873e7c61599e3e23c85b69d3216d167f0e3");
}

#[test]
fn fuzz_ntfs_root_dir_oom_87acc2eb5d38a2e0b5a02ea82d140099caceba70() {
    run_fuzz_ntfs_root_dir_artifact("oom-87acc2eb5d38a2e0b5a02ea82d140099caceba70");
}

#[test]
fn fuzz_ntfs_root_dir_oom_89fc23beb25119e5410afdb40def4d943fc46788() {
    run_fuzz_ntfs_root_dir_artifact("oom-89fc23beb25119e5410afdb40def4d943fc46788");
}

#[test]
fn fuzz_ntfs_root_dir_oom_af3a718859b7fb8a987e343283569660f53a48b5() {
    run_fuzz_ntfs_root_dir_artifact("oom-af3a718859b7fb8a987e343283569660f53a48b5");
}

#[test]
fn fuzz_ntfs_root_dir_oom_b48e9d82cd59c6ca7a3c974029665ef4a6cde2d7() {
    run_fuzz_ntfs_root_dir_artifact("oom-b48e9d82cd59c6ca7a3c974029665ef4a6cde2d7");
}

#[test]
fn fuzz_ntfs_root_dir_oom_c05ba10a3a362027598b0f02de25e9913b103c56() {
    run_fuzz_ntfs_root_dir_artifact("oom-c05ba10a3a362027598b0f02de25e9913b103c56");
}

#[test]
fn fuzz_ntfs_root_dir_oom_c68c4fde72bf4c0af2c1f8b8aab1bcf65d5e0e4e() {
    run_fuzz_ntfs_root_dir_artifact("oom-c68c4fde72bf4c0af2c1f8b8aab1bcf65d5e0e4e");
}

#[test]
fn fuzz_ntfs_root_dir_oom_d0964bbc4bb43204157f7b0fb48c455a3405607c() {
    run_fuzz_ntfs_root_dir_artifact("oom-d0964bbc4bb43204157f7b0fb48c455a3405607c");
}

#[test]
fn fuzz_ntfs_root_dir_oom_d62466970952a985bc9cf88dcc24d0e7a3d119f1() {
    run_fuzz_ntfs_root_dir_artifact("oom-d62466970952a985bc9cf88dcc24d0e7a3d119f1");
}

#[test]
fn fuzz_ntfs_root_dir_oom_da39a3ee5e6b4b0d3255bfef95601890afd80709() {
    run_fuzz_ntfs_root_dir_artifact("oom-da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn fuzz_ntfs_root_dir_oom_e425477c694c14023093cd89888c56571f4d4ecc() {
    run_fuzz_ntfs_root_dir_artifact("oom-e425477c694c14023093cd89888c56571f4d4ecc");
}

#[test]
fn fuzz_ntfs_root_dir_oom_f47df9339cade0f8375c336c316eaed7dd4a9859() {
    run_fuzz_ntfs_root_dir_artifact("oom-f47df9339cade0f8375c336c316eaed7dd4a9859");
}

#[test]
fn fuzz_ntfs_root_dir_oom_f6592e0eaa126c6e7183ec85f5a7f5fe1d78ec07() {
    run_fuzz_ntfs_root_dir_artifact("oom-f6592e0eaa126c6e7183ec85f5a7f5fe1d78ec07");
}

#[test]
fn fuzz_ntfs_root_dir_oom_fcf662211efae6f7754ca16c701e109cca7645f0() {
    run_fuzz_ntfs_root_dir_artifact("oom-fcf662211efae6f7754ca16c701e109cca7645f0");
}

// Slow-unit regression tests.

#[test]
fn fuzz_ntfs_root_dir_slow_unit_66a9e23f0325fa1d10b5e65ddc6341826a793a9d() {
    run_fuzz_ntfs_root_dir_artifact("slow-unit-66a9e23f0325fa1d10b5e65ddc6341826a793a9d");
}

#[test]
fn fuzz_ntfs_root_dir_slow_unit_84294ea51d556a08f11e930a0b2e743fdef0cfd1() {
    run_fuzz_ntfs_root_dir_artifact("slow-unit-84294ea51d556a08f11e930a0b2e743fdef0cfd1");
}

#[test]
fn fuzz_ntfs_root_dir_slow_unit_9249f801ae5cb0efab4bf9e81dfc80dff6067a44() {
    run_fuzz_ntfs_root_dir_artifact("slow-unit-9249f801ae5cb0efab4bf9e81dfc80dff6067a44");
}
