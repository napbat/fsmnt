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

#[cfg(feature = "std")]
struct CorruptTreeReader {
    file: File,
    tree_uuid: [u8; 16],
    corrupt: bool,
    position: u64,
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

fn volume() -> Option<Btrfs<Cursor<Vec<u8>>>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), FIXTURE)?;
    let mut volume = Btrfs::new(Cursor::new(bytes)).expect("open fixture superblock");
    volume.initialize().expect("bootstrap fixture trees");
    Some(volume)
}

#[cfg(feature = "std")]
fn multi_fixture_paths() -> Option<[PathBuf; 2]> {
    let first = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-multi-1.img");
    let second = fixture_path(env!("CARGO_MANIFEST_DIR"), "testdata/btrfs-multi-2.img");
    (first.exists() && second.exists()).then_some([first, second])
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
    let mut output = Vec::new();
    for number in 1..=count {
        output.extend_from_slice(format!("{prefix}-{number:05}\n").as_bytes());
    }
    output
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
        assert_eq!(
            volume.read_file(file).expect("decompress file"),
            numbered_lines(&format!("compressed-{compression}-line"), 8192),
            "{compression} contents"
        );
    }
}

#[cfg(feature = "std")]
#[test]
fn multi_device_fixture_rejects_missing_and_duplicate_members() {
    let Some([first, _second]) = multi_fixture_paths() else {
        return;
    };
    let missing = Btrfs::new(File::open(&first).expect("first member"));
    assert!(matches!(
        missing,
        Err(BtrfsError::DeviceCountMismatch {
            expected: 2,
            actual: 1
        })
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
