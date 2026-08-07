//! End-to-end traversal checks against a real `mkfs.btrfs` image.

#[cfg(feature = "std")]
use std::cell::Cell;
#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "std")]
use std::path::PathBuf;
#[cfg(feature = "std")]
use std::rc::Rc;

use fs_btrfs::{Btrfs, BtrfsDirEntry, BtrfsError, BtrfsFileType};
#[cfg(feature = "std")]
use fsmnt_testkit::fixture_path;
use fsmnt_testkit::{Cursor, read_optional_fixture};

const FIXTURE: &str = "testdata/btrfs-basic.img";
const SUBVOLUME_FIXTURE: &str = "testdata/btrfs-subvolumes.img";
#[cfg(feature = "std")]
const LOG_REPLAY_FIXTURE: &str = "testdata/btrfs-log-replay.img";
#[cfg(feature = "std")]
const EXTENT_TREE_V2_FIXTURE: &str = "testdata/btrfs-extent-tree-v2.img";
#[cfg(feature = "std")]
const EXTENT_TREE_V2_PATTERN: &[u8] = b"fsmnt extent tree v2 checksum pattern 0123456789abcdef\n";

#[cfg(feature = "std")]
struct CorruptTreeReader {
    file: File,
    tree_uuid: [u8; 16],
    corrupt: bool,
    position: u64,
    corruptions: Rc<Cell<u32>>,
}

#[cfg(feature = "std")]
struct CorruptPayloadReader {
    file: File,
    needle: Vec<u8>,
    corrupt: bool,
    corruptions: Rc<Cell<u32>>,
}

#[cfg(feature = "std")]
impl CorruptTreeReader {
    fn new(path: &PathBuf, tree_uuid: [u8; 16], corrupt: bool, corruptions: Rc<Cell<u32>>) -> Self {
        Self {
            file: File::open(path).expect("fixture member"),
            tree_uuid,
            corrupt,
            position: 0,
            corruptions,
        }
    }
}

#[cfg(feature = "std")]
impl Read for CorruptTreeReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let start = self.position;
        let read = self.file.read(buffer)?;
        self.position = self
            .position
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if self.corrupt
            && read > 101
            && !(0x1_0000..0x1_1000).contains(&start)
            && buffer.get(32..48) == Some(self.tree_uuid.as_slice())
        {
            buffer[101] ^= 1;
            self.corruptions
                .set(self.corruptions.get().saturating_add(1));
        }
        Ok(read)
    }
}

#[cfg(feature = "std")]
impl Seek for CorruptTreeReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.position = self.file.seek(position)?;
        Ok(self.position)
    }
}

#[cfg(feature = "std")]
impl CorruptPayloadReader {
    fn new(path: &PathBuf, needle: &[u8], corrupt: bool, corruptions: Rc<Cell<u32>>) -> Self {
        Self {
            file: File::open(path).expect("fixture member"),
            needle: needle.to_vec(),
            corrupt,
            corruptions,
        }
    }
}

#[cfg(feature = "std")]
impl Read for CorruptPayloadReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read(buffer)?;
        if self.corrupt
            && let Some(offset) = buffer[..read]
                .windows(self.needle.len())
                .position(|window| window == self.needle)
        {
            buffer[offset] ^= 1;
            self.corruptions
                .set(self.corruptions.get().saturating_add(1));
        }
        Ok(read)
    }
}

#[cfg(feature = "std")]
impl Seek for CorruptPayloadReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

fn volume() -> Option<Btrfs<Cursor<Vec<u8>>>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), FIXTURE)?;
    let mut volume = Btrfs::new(Cursor::new(bytes)).expect("open fixture superblock");
    volume.initialize().expect("bootstrap fixture trees");
    Some(volume)
}

fn subvolume_fixture() -> Option<Btrfs<Cursor<Vec<u8>>>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), SUBVOLUME_FIXTURE)?;
    let mut volume = Btrfs::new(Cursor::new(bytes)).expect("open subvolume fixture");
    volume
        .initialize()
        .expect("bootstrap subvolume fixture trees");
    Some(volume)
}

#[cfg(feature = "std")]
fn multi_fixture_paths() -> Option<[PathBuf; 2]> {
    let first = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-multi-1.img");
    let second = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-multi-2.img");
    (first.exists() && second.exists()).then_some([first, second])
}

#[cfg(feature = "std")]
fn parity_fixture_paths(profile: &str, member_count: usize) -> Option<Vec<PathBuf>> {
    let paths: Vec<PathBuf> = (1..=member_count)
        .map(|member| {
            fixture_path(
                env!("CARGO_MANIFEST_DIR"),
                format!("testdata/btrfs-{profile}-{member}.img"),
            )
        })
        .collect();
    paths.iter().all(|path| path.exists()).then_some(paths)
}

#[cfg(feature = "std")]
fn seed_fixture_paths() -> Option<[PathBuf; 3]> {
    let base = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-seed-base.img");
    let middle = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-seed-middle.img");
    let top = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-seed-top.img");
    (base.exists() && middle.exists() && top.exists()).then_some([base, middle, top])
}

#[cfg(feature = "std")]
fn parity_volume(profile: &str, member_count: usize, missing: &[usize]) -> Option<Btrfs<File>> {
    let paths = parity_fixture_paths(profile, member_count)?;
    let readers = paths
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !missing.contains(index))
        .map(|(_, path)| File::open(path).expect("parity member"))
        .collect();
    let mut volume = Btrfs::from_devices(readers).expect("open available parity members");
    volume
        .initialize()
        .expect("bootstrap degraded parity volume");
    Some(volume)
}

#[cfg(feature = "std")]
fn multi_volume(reverse: bool) -> Option<Btrfs<File>> {
    let [first, second] = multi_fixture_paths()?;
    let readers = if reverse {
        vec![
            File::open(second).expect("second member"),
            File::open(first).expect("first member"),
        ]
    } else {
        vec![
            File::open(first).expect("first member"),
            File::open(second).expect("second member"),
        ]
    };
    let mut volume = Btrfs::from_devices(readers).expect("open both members");
    volume.initialize().expect("bootstrap mirrored metadata");
    Some(volume)
}

#[cfg(feature = "std")]
fn numbered_lines(prefix: &str, count: u32) -> Vec<u8> {
    numbered_lines_with_width(prefix, 5, count)
}

#[cfg(feature = "std")]
fn numbered_lines_with_width(prefix: &str, width: usize, count: u32) -> Vec<u8> {
    let mut output = Vec::new();
    for number in 1..=count {
        output.extend_from_slice(format!("{prefix}-{number:0width$}\n").as_bytes());
    }
    output
}

#[cfg(feature = "std")]
fn repeated_pattern_range(offset: usize, length: usize) -> Vec<u8> {
    (offset..offset.saturating_add(length))
        .map(|index| EXTENT_TREE_V2_PATTERN[index % EXTENT_TREE_V2_PATTERN.len()])
        .collect()
}

#[cfg(feature = "std")]
fn patterned_bytes(length: usize, multiplier: usize, addend: usize, modulus: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let value = index
                .checked_mul(multiplier)
                .and_then(|value| value.checked_add(addend))
                .expect("fixture pattern arithmetic")
                % modulus;
            u8::try_from(value).expect("fixture pattern modulus fits u8")
        })
        .collect()
}

#[cfg(feature = "std")]
fn assert_parity_contents(profile: &str, member_count: usize, missing: &[usize], expected: &[u8]) {
    let mut volume =
        parity_volume(profile, member_count, missing).expect("generated parity fixture");
    let file = volume
        .resolve_path([b"parity.txt".as_slice()])
        .expect("parity file");
    assert_eq!(
        volume.read_file(file).expect("read parity file"),
        expected,
        "{profile} with missing members {missing:?}"
    );

    let offset = 32_768_u64;
    let offset_index = usize::try_from(offset).expect("range offset");
    let mut range = vec![0_u8; 196_608];
    let count = volume
        .read_file_range(file, offset, &mut range)
        .expect("read parity range");
    assert_eq!(count, range.len());
    assert_eq!(
        range,
        expected[offset_index..offset_index + count],
        "{profile} range with missing members {missing:?}"
    );
}

#[cfg(feature = "std")]
fn read_named<R>(volume: &mut Btrfs<R>, name: &[u8]) -> Vec<u8>
where
    R: fs_btrfs::io::Read + fs_btrfs::io::Seek,
{
    let entry = volume.resolve_path([name]).expect("seed-chain file");
    volume.read_file(entry).expect("read seed-chain file")
}

#[cfg(feature = "std")]
fn fixture_fsid(path: &PathBuf) -> [u8; 16] {
    let mut file = File::open(path).expect("fixture member");
    file.seek(SeekFrom::Start(0x1_0020))
        .expect("seek to superblock FSID");
    let mut fsid = [0_u8; 16];
    file.read_exact(&mut fsid).expect("read superblock FSID");
    fsid
}

#[test]
fn real_fixture_traverses_directories_and_reads_files() {
    let Some(mut volume) = volume() else {
        return;
    };
    let root = volume.root().expect("root");
    let entries = volume.read_dir(root).expect("root entries");
    let names: Vec<&[u8]> = entries.iter().map(BtrfsDirEntry::name).collect();

    assert!(names.contains(&b"hello.txt".as_slice()));
    assert!(names.contains(&b"nested".as_slice()));
    assert!(names.contains(&b"empty".as_slice()));

    let hello = volume
        .resolve_path([b"hello.txt".as_slice()])
        .expect("hello entry");
    assert_eq!(
        volume.read_file(hello).expect("hello contents"),
        b"hello from fsmnt btrfs\n"
    );
    let mut range = [0xa5_u8; 8];
    let count = volume
        .read_file_range(hello, 6, &mut range)
        .expect("hello range");
    assert_eq!(count, range.len());
    assert_eq!(&range, b"from fsm");

    let note = volume
        .resolve_path([
            b"nested".as_slice(),
            b"deeper".as_slice(),
            b"note.txt".as_slice(),
        ])
        .expect("nested note");
    assert_eq!(
        volume.read_file(note).expect("note contents"),
        b"nested file contents\n"
    );
}

#[cfg(feature = "std")]
#[test]
fn real_extent_tree_v2_fixture_reads_global_checksum_roots() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), EXTENT_TREE_V2_FIXTURE);
    if !path.exists() {
        return;
    }
    let mut volume =
        Btrfs::new(File::open(path).expect("extent-tree-v2 fixture")).expect("open fixture");
    assert_eq!(volume.superblock().global_root_count(), 4);
    volume
        .initialize()
        .expect("load global roots and block-group assignments");

    let marker = volume
        .resolve_path([b"marker.txt".as_slice()])
        .expect("marker");
    assert_eq!(
        volume.read_file(marker).expect("marker contents"),
        b"extent-tree-v2 through global checksum roots\n"
    );

    let data = volume
        .resolve_path([b"global-roots.bin".as_slice()])
        .expect("global-root data");
    for offset in [
        0_usize,
        8 * 1024 * 1024 - 2048,
        40 * 1024 * 1024,
        63 * 1024 * 1024,
        100 * 1024 * 1024,
        140 * 1024 * 1024,
        159 * 1024 * 1024,
    ] {
        let mut actual = vec![0_u8; 8192];
        let count = volume
            .read_file_range(
                data,
                u64::try_from(offset).expect("fixture offset fits u64"),
                &mut actual,
            )
            .expect("checksummed range");
        assert_eq!(count, actual.len());
        assert_eq!(actual, repeated_pattern_range(offset, actual.len()));
    }
}

#[test]
fn real_fixture_preserves_sparse_holes_and_symlink_targets() {
    let Some(mut volume) = volume() else {
        return;
    };
    let sparse = volume
        .resolve_path([b"sparse.bin".as_slice()])
        .expect("sparse entry");
    let bytes = volume.read_file(sparse).expect("sparse contents");
    assert_eq!(bytes.len(), 1_048_576);
    assert!(bytes[..bytes.len() - 4].iter().all(|byte| *byte == 0));
    assert_eq!(&bytes[bytes.len() - 4..], b"tail");
    let mut tail = [0xa5_u8; 8];
    assert_eq!(
        volume
            .read_file_range(sparse, 1_048_568, &mut tail)
            .expect("sparse tail range"),
        tail.len()
    );
    assert_eq!(&tail, b"\0\0\0\0tail");
    let mut past_end = [0xa5_u8; 8];
    assert_eq!(
        volume
            .read_file_range(sparse, 1_048_576, &mut past_end)
            .expect("read at end"),
        0
    );
    assert_eq!(past_end, [0xa5; 8]);

    let link = volume
        .resolve_path([b"note-link".as_slice()])
        .expect("symlink entry");
    assert_eq!(
        volume.inode(link).expect("symlink inode").file_type(),
        BtrfsFileType::SymbolicLink
    );
    assert_eq!(
        volume.read_file(link).expect("symlink target"),
        b"nested/deeper/note.txt"
    );
}

#[test]
fn real_fixture_selects_default_nested_and_snapshot_roots() {
    let Some(mut volume) = subvolume_fixture() else {
        return;
    };

    let default_id = volume
        .default_subvolume_id()
        .expect("configured default subvolume");
    assert_ne!(default_id, 5);
    let default_root = volume.root().expect("default root");
    assert_eq!(default_root.tree_id(), default_id);
    let root_marker = volume
        .resolve_path_from(
            default_root,
            [b"etc".as_slice(), b"root-marker.txt".as_slice()],
        )
        .expect("default root marker");
    assert_eq!(
        volume
            .read_file(root_marker)
            .expect("default root contents"),
        b"selected default root\n"
    );

    let home = volume
        .subvolume_at_path([b"home".as_slice()])
        .expect("home subvolume");
    let home_marker = volume
        .resolve_path_from(home, [b"home-marker.txt".as_slice()])
        .expect("home marker");
    assert_eq!(
        volume.read_file(home_marker).expect("home contents"),
        b"selected home subvolume\n"
    );

    let nested = volume
        .subvolume_at_path([
            b"root".as_slice(),
            b"var".as_slice(),
            b"lib".as_slice(),
            b"nested".as_slice(),
        ])
        .expect("nested subvolume");
    let nested_marker = volume
        .resolve_path_from(nested, [b"nested-marker.txt".as_slice()])
        .expect("nested marker");
    assert_eq!(
        volume.read_file(nested_marker).expect("nested contents"),
        b"selected nested subvolume\n"
    );

    let snapshot = volume
        .subvolume_at_path([b"root-snapshot".as_slice()])
        .expect("read-only snapshot");
    let snapshot_marker = volume
        .resolve_path_from(snapshot, [b"etc".as_slice(), b"root-marker.txt".as_slice()])
        .expect("snapshot marker");
    assert_eq!(
        volume
            .read_file(snapshot_marker)
            .expect("snapshot contents"),
        b"selected default root\n"
    );

    assert!(matches!(
        volume.subvolume_at_path([b"root".as_slice(), b"etc".as_slice()]),
        Err(BtrfsError::NotASubvolume)
    ));
}

#[test]
fn real_fixture_rejects_corrupt_checksummed_file_data() {
    let Some(bytes) = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), FIXTURE) else {
        return;
    };
    let needle = b"fsmnt-checksum-fixture-line-0777\n";
    let offsets: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect();
    assert!(
        !offsets.is_empty(),
        "fixture must contain the checksummed payload"
    );
    for offset in offsets {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        let mut volume = Btrfs::new(Cursor::new(corrupt)).expect("open corrupt fixture");
        volume.initialize().expect("metadata remains valid");
        let file = volume
            .resolve_path([b"checksummed.txt".as_slice()])
            .expect("checksummed entry");
        if matches!(
            volume.read_file(file),
            Err(BtrfsError::InvalidChecksum {
                structure: "data sector",
                ..
            })
        ) {
            return;
        }
    }
    panic!("none of the fixture payload copies was the mapped data extent");
}

#[cfg(feature = "std")]
#[test]
fn real_multi_device_fixture_reads_across_raid0_stripes() {
    let Some(mut volume) = multi_volume(true) else {
        return;
    };
    let file = volume
        .resolve_path([b"striped.txt".as_slice()])
        .expect("striped file");
    let actual = volume.read_file(file).expect("read RAID0 file");

    assert_eq!(actual, numbered_lines("multi-device-line", 32_768));
    let mut range = vec![0_u8; 200_000];
    let count = volume
        .read_file_range(file, 60_000, &mut range)
        .expect("read RAID0 range");
    assert_eq!(count, range.len());
    assert_eq!(&range, &actual[60_000..260_000]);
}

#[cfg(feature = "std")]
#[test]
fn multi_device_discovery_reads_all_member_identities_from_one_member() {
    let Some([first, _second]) = multi_fixture_paths() else {
        return;
    };
    let mut volume =
        Btrfs::new(File::open(first).expect("first member")).expect("open first member");
    let identities = volume
        .discover_device_identities()
        .expect("discover chunk-tree devices");

    assert_eq!(
        identities
            .iter()
            .map(|identity| identity.device_id())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_ne!(
        identities[0].device_uuid(),
        identities[1].device_uuid(),
        "distinct member IDs must retain distinct UUIDs"
    );
}

#[cfg(feature = "std")]
#[test]
fn real_multi_device_fixture_reads_every_compression_format() {
    let Some(mut volume) = multi_volume(false) else {
        return;
    };
    for compression in ["zlib", "lzo", "zstd"] {
        let name = format!("{compression}.txt");
        let file = volume
            .resolve_path([name.as_bytes()])
            .expect("compressed file");
        let expected = numbered_lines(&format!("compressed-{compression}-line"), 8192);
        assert_eq!(volume.read_file(file).expect("decompress file"), expected);
        let mut range = vec![0_u8; 50_000];
        let count = volume
            .read_file_range(file, 120_000, &mut range)
            .expect("decompress range");
        assert_eq!(count, range.len());
        assert_eq!(&range, &expected[120_000..170_000], "{compression} range");
    }
}

#[cfg(feature = "std")]
#[test]
fn multi_device_fixture_rejects_missing_and_duplicate_members() {
    let Some([first, _second]) = multi_fixture_paths() else {
        return;
    };
    let mut missing =
        Btrfs::new(File::open(&first).expect("first member")).expect("open degraded member");
    assert!(matches!(
        missing.initialize(),
        Err(BtrfsError::InsufficientDevicesForChunk { .. })
    ));

    let duplicate = Btrfs::from_devices(vec![
        File::open(&first).expect("first member"),
        File::open(first).expect("duplicate first member"),
    ]);
    assert!(matches!(
        duplicate,
        Err(BtrfsError::DuplicateDevice { device_id: 1 })
    ));
}

#[cfg(feature = "std")]
#[test]
fn mirrored_metadata_retries_after_checksum_failure() {
    let Some([first, second]) = multi_fixture_paths() else {
        return;
    };
    let fsid = fixture_fsid(&first);
    let corruptions = Rc::new(Cell::new(0));
    let readers = vec![
        CorruptTreeReader::new(&first, fsid, true, Rc::clone(&corruptions)),
        CorruptTreeReader::new(&second, fsid, false, Rc::clone(&corruptions)),
    ];
    let mut volume = Btrfs::from_devices(readers).expect("open both members");
    volume.initialize().expect("retry valid mirrored metadata");
    let root = volume.root().expect("root after mirror retry");
    assert!(!volume.read_dir(root).expect("root entries").is_empty());
    assert!(
        corruptions.get() > 0,
        "the faulty mirror must have been exercised"
    );
}

#[cfg(feature = "std")]
#[test]
fn real_raid5_fixture_reads_healthy_and_each_degraded_member() {
    if parity_fixture_paths("raid5", 3).is_none() {
        return;
    }
    let expected = numbered_lines_with_width("raid5-data-line", 6, 131_072);
    assert_parity_contents("raid5", 3, &[], &expected);
    for missing in 0..3 {
        assert_parity_contents("raid5", 3, &[missing], &expected);
    }
}

#[cfg(feature = "std")]
#[test]
fn real_raid6_fixture_reads_healthy_and_up_to_two_degraded_members() {
    if parity_fixture_paths("raid6", 4).is_none() {
        return;
    }
    let expected = numbered_lines_with_width("raid6-data-line", 6, 131_072);
    assert_parity_contents("raid6", 4, &[], &expected);
    for first in 0..4 {
        assert_parity_contents("raid6", 4, &[first], &expected);
        for second in first + 1..4 {
            assert_parity_contents("raid6", 4, &[first, second], &expected);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn parity_fixtures_reject_too_many_missing_members() {
    for (profile, member_count, retained) in [("raid5", 3_usize, 1_usize), ("raid6", 4, 1)] {
        let Some(paths) = parity_fixture_paths(profile, member_count) else {
            return;
        };
        let mut volume = Btrfs::new(File::open(&paths[retained]).expect("retained parity member"))
            .expect("open degraded parity member");
        assert!(
            matches!(
                volume.initialize(),
                Err(BtrfsError::InsufficientDevicesForChunk { .. })
            ),
            "{profile} must reject excessive member loss"
        );
    }
}

#[cfg(feature = "std")]
#[test]
fn raid6_checksum_retry_recovers_two_silently_corrupt_data_members() {
    let Some(paths) = parity_fixture_paths("raid6", 4) else {
        return;
    };
    let corruptions: Vec<Rc<Cell<u32>>> = paths.iter().map(|_| Rc::new(Cell::new(0))).collect();
    let readers = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            CorruptPayloadReader::new(
                path,
                b"raid6-data-line-",
                index < 2,
                Rc::clone(&corruptions[index]),
            )
        })
        .collect();
    let mut volume = Btrfs::from_devices(readers).expect("open corrupt RAID6 members");
    volume.initialize().expect("bootstrap RAID6 metadata");
    let file = volume
        .resolve_path([b"parity.txt".as_slice()])
        .expect("RAID6 parity file");
    assert_eq!(
        volume.read_file(file).expect("recover corrupt RAID6 data"),
        numbered_lines_with_width("raid6-data-line", 6, 131_072)
    );
    assert!(
        corruptions[..2].iter().all(|counter| counter.get() > 0),
        "both corrupt data members must be exercised"
    );
}

#[cfg(feature = "std")]
#[test]
fn real_seed_chain_reads_each_layer_and_standalone_seed() {
    let Some([base, middle, top]) = seed_fixture_paths() else {
        return;
    };

    let mut base_volume =
        Btrfs::new(File::open(&base).expect("base seed")).expect("open base seed");
    base_volume.initialize().expect("initialize base seed");
    assert!(base_volume.superblock().is_seeding());
    assert_eq!(read_named(&mut base_volume, b"layer.txt"), b"base layer\n");
    assert_eq!(
        read_named(&mut base_volume, b"base-only.txt"),
        numbered_lines("seed-base-line", 32_768)
    );

    let mut middle_volume = Btrfs::from_devices(vec![
        File::open(&base).expect("base seed"),
        File::open(&middle).expect("middle seed"),
    ])
    .expect("open middle seed chain");
    middle_volume
        .initialize()
        .expect("initialize middle seed chain");
    assert!(middle_volume.superblock().is_seeding());
    assert_eq!(
        read_named(&mut middle_volume, b"layer.txt"),
        b"middle layer\n"
    );
    assert_eq!(
        read_named(&mut middle_volume, b"base-only.txt"),
        numbered_lines("seed-base-line", 32_768)
    );
    assert_eq!(
        read_named(&mut middle_volume, b"middle-only.txt"),
        numbered_lines("seed-middle-line", 32_768)
    );

    let mut top_volume = Btrfs::from_devices(vec![
        File::open(&middle).expect("middle seed"),
        File::open(&top).expect("top sprout"),
        File::open(&base).expect("base seed"),
    ])
    .expect("open complete seed chain");
    top_volume
        .initialize()
        .expect("initialize complete seed chain");
    assert!(!top_volume.superblock().is_seeding());
    assert_eq!(read_named(&mut top_volume, b"layer.txt"), b"top layer\n");
    assert_eq!(
        read_named(&mut top_volume, b"base-only.txt"),
        numbered_lines("seed-base-line", 32_768)
    );
    assert_eq!(
        read_named(&mut top_volume, b"middle-only.txt"),
        numbered_lines("seed-middle-line", 32_768)
    );
    assert_eq!(
        read_named(&mut top_volume, b"top-only.txt"),
        numbered_lines("seed-top-line", 32_768)
    );
}

#[cfg(feature = "std")]
#[test]
fn seed_chain_discovery_finds_members_across_distinct_fsids() {
    let Some([_base, _middle, top]) = seed_fixture_paths() else {
        return;
    };
    let mut volume = Btrfs::new(File::open(top).expect("top sprout")).expect("open top sprout");
    let identities = volume
        .discover_device_identities()
        .expect("discover seed-chain devices");

    assert_eq!(
        identities
            .iter()
            .map(|identity| identity.device_id())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[cfg(feature = "std")]
#[test]
fn seed_chain_rejects_a_missing_dependency() {
    let Some([base, middle, top]) = seed_fixture_paths() else {
        return;
    };
    for readers in [
        vec![
            File::open(&middle).expect("middle seed"),
            File::open(&top).expect("top sprout"),
        ],
        vec![
            File::open(&base).expect("base seed"),
            File::open(&top).expect("top sprout"),
        ],
    ] {
        let mut volume = Btrfs::from_devices(readers).expect("open incomplete seed chain");
        assert!(matches!(
            volume.initialize(),
            Err(BtrfsError::InsufficientDevicesForChunk { .. })
        ));
    }
}

#[cfg(feature = "std")]
#[test]
fn real_tree_log_replays_fsync_create_modify_delete_rename_and_resize() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), LOG_REPLAY_FIXTURE);
    if !path.exists() {
        return;
    }
    let mut volume =
        Btrfs::new(File::open(path).expect("tree-log fixture")).expect("open tree-log fixture");
    assert!(volume.superblock().generation() > 0);
    assert!(volume.superblock().log_root().is_some_and(|logical| {
        logical.is_multiple_of(u64::from(volume.superblock().sector_size()))
    }));
    assert_eq!(volume.superblock().log_root_level(), 0);
    assert_eq!(volume.superblock().log_root_transid(), 0);
    volume.initialize().expect("project pending tree log");

    let root = volume.root().expect("tree-log root");
    let names: Vec<Vec<u8>> = volume
        .read_dir(root)
        .expect("replayed directory")
        .into_iter()
        .map(|entry| entry.name().to_vec())
        .collect();
    assert_eq!(
        names,
        [
            b"modified.txt".to_vec(),
            b"truncated.txt".to_vec(),
            b"extended.txt".to_vec(),
            b"large-modified.bin".to_vec(),
            b"large-hole.bin".to_vec(),
            b"large-truncated.bin".to_vec(),
            b"large-extended.bin".to_vec(),
            b"created.txt".to_vec(),
            b"large-created.bin".to_vec(),
            b"rename-new.txt".to_vec(),
        ]
    );

    assert_eq!(
        read_named(&mut volume, b"created.txt"),
        b"created through tree log\n"
    );
    assert_eq!(
        read_named(&mut volume, b"modified.txt"),
        b"logged version\n"
    );
    assert_eq!(
        read_named(&mut volume, b"rename-new.txt"),
        b"rename after commit\n"
    );
    assert_eq!(read_named(&mut volume, b"truncated.txt"), b"tiny");
    assert_eq!(
        read_named(&mut volume, b"extended.txt"),
        b"committed prefix\nlogged suffix\n"
    );
    assert!(matches!(
        volume.resolve_path([b"deleted.txt".as_slice()]),
        Err(BtrfsError::NotFound)
    ));
    assert!(matches!(
        volume.resolve_path([b"rename-old.txt".as_slice()]),
        Err(BtrfsError::NotFound)
    ));
}

#[cfg(feature = "std")]
#[test]
fn real_tree_log_replays_checksummed_extents_overwrites_holes_and_size_changes() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), LOG_REPLAY_FIXTURE);
    if !path.exists() {
        return;
    }
    let mut volume =
        Btrfs::new(File::open(path).expect("tree-log fixture")).expect("open tree-log fixture");
    volume.initialize().expect("project pending tree log");

    assert_eq!(
        read_named(&mut volume, b"large-created.bin"),
        patterned_bytes(786_432, 23, 7, 229)
    );

    let mut modified = patterned_bytes(1_048_576, 17, 3, 251);
    modified[327_680..524_288].copy_from_slice(&patterned_bytes(196_608, 29, 11, 227));
    assert_eq!(read_named(&mut volume, b"large-modified.bin"), modified);

    let mut hole = patterned_bytes(524_288, 11, 5, 241);
    hole[131_072..262_144].fill(0);
    assert_eq!(read_named(&mut volume, b"large-hole.bin"), hole);

    let truncated = patterned_bytes(786_432, 13, 9, 239);
    assert_eq!(
        read_named(&mut volume, b"large-truncated.bin"),
        truncated[..100_003]
    );

    let mut extended = patterned_bytes(131_072, 19, 1, 233);
    extended.extend(patterned_bytes(196_608, 31, 13, 223));
    assert_eq!(read_named(&mut volume, b"large-extended.bin"), extended);
}
