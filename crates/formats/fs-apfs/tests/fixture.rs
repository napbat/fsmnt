//! Real-image integration tests for the `fs-apfs` parser.
//!
//! These tests run against APFS fixture images under `testdata/`. The
//! images are not committed — generating them needs `mkapfs` and root (see
//! `testdata/README.md`) — so each test loads its fixture lazily and skips
//! with a diagnostic when it is absent. A checkout without the fixtures still
//! builds and passes `cargo test`; CI gains the coverage once the fixtures
//! are generated.

use std::io::Cursor;

/// Loads a fixture image from `testdata/`, or returns `None` (with a note)
/// when it has not been generated.
fn load_fixture(name: &str) -> Option<Cursor<Vec<u8>>> {
    let bytes = fsmnt_testkit::read_optional_fixture(
        env!("CARGO_MANIFEST_DIR"),
        format!("testdata/{name}"),
    );
    bytes.map(Cursor::new).or_else(|| {
        eprintln!(
            "skipping: APFS fixture {name} not present \
             (run crates/formats/fs-apfs/testdata/gen-fixtures.sh)"
        );
        None
    })
}

#[test]
fn mounts_the_apfs_fixture_and_walks_its_root() {
    let Some(mut reader) = load_fixture("apfs.img") else {
        return;
    };
    let apfs = fs_apfs::Apfs::new(&mut reader).expect("mount the APFS container");
    assert!(apfs.volume_count() >= 1, "container must have a volume");

    let volume = fs_apfs::Volume::open(&apfs, &mut reader, 0).expect("open volume 0");
    // The root directory must resolve and enumerate without error.
    assert_eq!(
        volume.resolve_path(&mut reader, "/").expect("resolve root"),
        2
    );
    let _ = volume
        .read_dir(&mut reader, 2)
        .expect("enumerate the root directory");
}

#[test]
fn enumerates_every_volume_of_a_multi_volume_fixture() {
    let Some(mut reader) = load_fixture("apfs-multi-volume.img") else {
        return;
    };
    let apfs = fs_apfs::Apfs::new(&mut reader).expect("mount the container");
    let volumes = apfs
        .volumes(&mut reader)
        .expect("enumerate volume superblocks");
    assert!(
        volumes.len() >= 2,
        "the multi-volume fixture must hold at least two volumes",
    );
    for index in 0..volumes.len() {
        // Every volume must open and expose a root directory.
        let volume = fs_apfs::Volume::open(&apfs, &mut reader, index).expect("open volume");
        let _ = volume
            .read_dir(&mut reader, 2)
            .expect("list the volume root");
    }
}
