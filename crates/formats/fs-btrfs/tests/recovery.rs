//! Recovery checks against a fixture with multiple committed root generations.

#![cfg(feature = "std")]

use std::cell::Cell;
use std::fs::File;
use std::path::Path;
use std::rc::Rc;

use fs_btrfs::{Btrfs, BtrfsSuperblock};
use fsmnt_testkit::{MutatingReader, fixture_path};

const FIXTURE: &str = "testdata/btrfs-root-recovery.img";
const STABLE_CONTENTS: &[u8] = b"survives historical root recovery\n";

fn corrupt_tree_reader(
    path: &Path,
    superblock: &BtrfsSuperblock,
    logical: u64,
    corruptions: Rc<Cell<u32>>,
) -> MutatingReader<File, impl FnMut(u64, &mut [u8])> {
    corrupt_trees_reader(path, superblock, [logical], corruptions)
}

fn corrupt_trees_reader(
    path: &Path,
    superblock: &BtrfsSuperblock,
    logicals: impl IntoIterator<Item = u64>,
    corruptions: Rc<Cell<u32>>,
) -> MutatingReader<File, impl FnMut(u64, &mut [u8])> {
    let tree_uuid = *superblock.tree_uuid();
    let logicals = logicals
        .into_iter()
        .map(u64::to_le_bytes)
        .collect::<Vec<_>>();
    MutatingReader::new(
        File::open(path).expect("recovery fixture"),
        move |_physical, data: &mut [u8]| {
            if data.len() > 101
                && data.get(32..48) == Some(tree_uuid.as_slice())
                && logicals
                    .iter()
                    .any(|logical| data.get(48..56) == Some(logical.as_slice()))
            {
                data[101] ^= 1;
                corruptions.set(corruptions.get().saturating_add(1));
            }
        },
    )
}

fn read_stable<R>(volume: &mut Btrfs<R>) -> Vec<u8>
where
    R: fs_btrfs::io::Read + fs_btrfs::io::Seek,
{
    let entry = volume
        .resolve_path([b"stable.txt".as_slice()])
        .expect("stable recovery file");
    volume.read_file(entry).expect("read stable recovery file")
}

#[test]
fn corrupt_live_root_recovers_through_historical_root() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), FIXTURE);
    if !path.exists() {
        return;
    }
    let baseline =
        Btrfs::new(File::open(&path).expect("recovery fixture")).expect("open recovery fixture");
    let live_generation = baseline.superblock().generation();
    let live_root = baseline.superblock().root();
    assert_eq!(baseline.superblock().root_backups().len(), 4);
    assert!(baseline.superblock().root_backups().iter().any(|backup| {
        backup.root_tree().generation() < live_generation
            && backup.root_tree().logical() != live_root
    }));

    let corruptions = Rc::new(Cell::new(0_u32));
    let reader = corrupt_tree_reader(
        &path,
        baseline.superblock(),
        live_root,
        Rc::clone(&corruptions),
    );
    let mut recovered = Btrfs::new(reader).expect("open corrupt-root fixture");
    recovered
        .initialize()
        .expect("recover from historical root tree");

    let recovery = recovered.recovery().expect("historical recovery metadata");
    assert!(recovery.generation() < live_generation);
    assert!(!recovery.used_backup_chunk_tree());
    assert_eq!(recovered.active_generation(), recovery.generation());
    assert!(
        corruptions.get() >= 2,
        "both live-root metadata replicas must be rejected"
    );
    assert_eq!(read_stable(&mut recovered), STABLE_CONTENTS);
}

#[test]
fn corrupt_live_and_historical_roots_fail_closed() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), FIXTURE);
    if !path.exists() {
        return;
    }
    let baseline =
        Btrfs::new(File::open(&path).expect("recovery fixture")).expect("open recovery fixture");
    let mut roots = vec![baseline.superblock().root()];
    roots.extend(
        baseline
            .superblock()
            .root_backups()
            .iter()
            .map(|backup| backup.root_tree().logical()),
    );
    roots.sort_unstable();
    roots.dedup();

    let corruptions = Rc::new(Cell::new(0_u32));
    let reader = corrupt_trees_reader(&path, baseline.superblock(), roots, Rc::clone(&corruptions));
    let mut damaged = Btrfs::new(reader).expect("open damaged fixture");
    let error = damaged
        .initialize()
        .expect_err("all candidate roots must be rejected");

    assert!(
        matches!(
            error,
            fs_btrfs::BtrfsError::InvalidChecksum {
                structure: "tree block",
                ..
            }
        ),
        "the live-root checksum error must remain authoritative: {error:?}"
    );
    assert_eq!(damaged.recovery(), None);
    assert!(
        corruptions.get() >= 2,
        "both live-root metadata replicas must be rejected"
    );
}

#[test]
fn corrupt_live_chunk_root_recovers_with_historical_chunk_tree() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), FIXTURE);
    if !path.exists() {
        return;
    }
    let baseline =
        Btrfs::new(File::open(&path).expect("recovery fixture")).expect("open recovery fixture");
    let live_generation = baseline.superblock().generation();
    let live_chunk_root = baseline.superblock().chunk_root();
    assert!(baseline.superblock().root_backups().iter().any(|backup| {
        backup.chunk_tree().logical() != live_chunk_root
            && backup.root_tree().generation() < live_generation
    }));

    let corruptions = Rc::new(Cell::new(0_u32));
    let reader = corrupt_tree_reader(
        &path,
        baseline.superblock(),
        live_chunk_root,
        Rc::clone(&corruptions),
    );
    let mut recovered = Btrfs::new(reader).expect("open corrupt-chunk fixture");
    recovered
        .initialize()
        .expect("recover with historical chunk tree");

    let recovery = recovered.recovery().expect("historical recovery metadata");
    assert!(recovery.generation() < live_generation);
    assert!(recovery.used_backup_chunk_tree());
    assert_eq!(recovered.active_generation(), recovery.generation());
    assert!(
        corruptions.get() >= 2,
        "both live chunk-root replicas must be rejected"
    );
    assert_eq!(read_stable(&mut recovered), STABLE_CONTENTS);
}
