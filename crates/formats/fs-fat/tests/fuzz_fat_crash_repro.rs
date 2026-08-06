//! Regression tests for inputs that previously crashed FAT fuzz targets.

use fs_common::iter::FsTryIterator;
use fsmnt_testkit::Cursor;

/// Regression harnesses for libFuzzer crashes found in FAT fuzz targets.
fn load_artifact(target: &str, file_name: &str) -> Option<Vec<u8>> {
    let relative_path = format!("../../../crashes/libfuzzer/{target}/{file_name}");
    let data = fsmnt_testkit::read_optional_fixture(env!("CARGO_MANIFEST_DIR"), &relative_path);
    if data.is_none() {
        eprintln!("SKIPPED: missing recorded libFuzzer artifact {relative_path}");
    }
    data
}

fn run_fuzz_fat_new_artifact(file_name: &str) {
    let Some(data) = load_artifact("fuzz_fat_new", file_name) else {
        return;
    };
    let mut cursor = Cursor::new(&data[..]);
    let _ = fs_fat::Fat::new(&mut cursor);
}

fn run_fuzz_fat_root_dir_artifact(file_name: &str) {
    let Some(data) = load_artifact("fuzz_fat_root_dir", file_name) else {
        return;
    };
    let mut cursor = Cursor::new(&data[..]);

    let Ok(fat) = fs_fat::Fat::new(&mut cursor) else {
        return;
    };

    let mut entries = fat.root_dir_entries();
    while let Some(entry) = entries.try_next(&mut cursor).unwrap_or(None) {
        let _ = entry.name();
        let _ = entry.attributes();
        let _ = entry.is_directory();
        let _ = entry.is_volume_id();
        let _ = entry.file_size();
        let _ = entry.first_cluster();
        let _ = entry.creation_time();
        let _ = entry.modification_time();
        let _ = entry.access_date();
    }
}

fn run_fuzz_fat_open_artifact(file_name: &str) {
    let Some(data) = load_artifact("fuzz_fat_open", file_name) else {
        return;
    };

    // The fuzz_fat_open target uses `arbitrary` to split the input into
    // image data and a path. For reproduction, we treat the entire blob
    // as the image and try opening the root.
    let mut cursor = Cursor::new(&data[..]);

    let Ok(fat) = fs_fat::Fat::new(&mut cursor) else {
        return;
    };

    // Try opening root (empty path).
    let Ok(file) = fat.open(&mut cursor, "/") else {
        return;
    };

    if file.is_directory()
        && let Ok(mut entries) = file.dir_entries()
    {
        while let Some(entry) = entries.try_next(&mut cursor).unwrap_or(None) {
            let _ = entry.name();
        }
    }
}

#[test]
fn fuzz_fat_new_crash_f6bfbb1d32d92efaa99234207e0a01116cd88f91() {
    run_fuzz_fat_new_artifact("crash-f6bfbb1d32d92efaa99234207e0a01116cd88f91");
}

#[test]
fn fuzz_fat_root_dir_crash_77241a6ee8a1310e7afcd6daaaae7c79cbdb9fd3() {
    run_fuzz_fat_root_dir_artifact("crash-77241a6ee8a1310e7afcd6daaaae7c79cbdb9fd3");
}

#[test]
fn fuzz_fat_open_crash_3df662e94592549cf84b7665609669ba1db8f10b() {
    run_fuzz_fat_open_artifact("crash-3df662e94592549cf84b7665609669ba1db8f10b");
}
