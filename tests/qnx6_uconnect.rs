//! Opt-in end-to-end coverage for the 2017 Dodge Durango Uconnect image.
//!
//! Set `FSMNT_UCONNECT_IMAGE` to the raw image path to run these assertions;
//! clean checkouts without the privately held image skip the test.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fsmnt::device::DetectedBootSector;
use fsmnt::{ImageOpenOptions, TargetFilesystem, image_layout, open_image_with_options};
use sha2::{Digest, Sha256};

fn fixture() -> Option<PathBuf> {
    std::env::var_os("FSMNT_UCONNECT_IMAGE").map(PathBuf::from)
}

#[derive(Default)]
struct Audit {
    directories: u64,
    files: u64,
    bytes: u64,
    largest_file: u64,
    digest: Sha256,
}

struct ExpectedVolume {
    uuid: &'static str,
    total_bytes: u64,
    free_bytes: u64,
    root_names: &'static [&'static str],
    directories: u64,
    files: u64,
    logical_bytes: u64,
    largest_file: u64,
    content_sha256: &'static str,
}

const EXPECTED_VOLUMES: [ExpectedVolume; 4] = [
    ExpectedVolume {
        uuid: "1eee57ed-fd97-4d3f-b8b3-867a6d550bd0",
        total_bytes: 10_792_992_768,
        free_bytes: 5_945_116_672,
        root_names: &[".boot", "app", "nav", "speech_service", "eq"],
        directories: 385,
        files: 4_740,
        logical_bytes: 4_778_622_776,
        largest_file: 321_737_028,
        content_sha256: "b7910ecd506cad4e4e1cd926f86af6254ac01f955ba76f80ffd303231413e4cf",
    },
    ExpectedVolume {
        uuid: "1b52ec41-75e4-45f7-b397-a19abdc70b2e",
        total_bytes: 3_886_022_656,
        free_bytes: 3_758_728_192,
        root_names: &[
            ".boot", "flags", "logs", "config", "download", "kona", "resource", "xletsdir", "ota",
            "ssl", "tmp",
        ],
        directories: 54,
        files: 94,
        logical_bytes: 95_327_573,
        largest_file: 21_907_080,
        content_sha256: "1d0dd72d794a54532112aff72844a072453ddb2502b93c31d6f16f97c90b79d2",
    },
    ExpectedVolume {
        uuid: "69e2ba15-6b85-4c2f-97d7-cf3612bdd0d5",
        total_bytes: 209_698_816,
        free_bytes: 203_046_912,
        root_names: &[".boot"],
        directories: 2,
        files: 0,
        logical_bytes: 0,
        largest_file: 0,
        content_sha256: "a970cfbd7f7c471ab2b757a939f47e3f7ee39dd20da94a0826b4ef9b7b2c460c",
    },
    ExpectedVolume {
        uuid: "8d7c5d5c-1209-402f-9eb8-b2b56469946d",
        total_bytes: 846_184_448,
        free_bytes: 819_406_848,
        root_names: &[".boot"],
        directories: 2,
        files: 0,
        logical_bytes: 0,
        largest_file: 0,
        content_sha256: "a970cfbd7f7c471ab2b757a939f47e3f7ee39dd20da94a0826b4ef9b7b2c460c",
    },
];

fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn assert_zero_extent(path: &Path, offset: u64, length: u64) {
    let mut image = std::fs::File::open(path).expect("open Uconnect image for zero-extent check");
    image
        .seek(SeekFrom::Start(offset))
        .expect("seek to QNX4-typed extent");
    let mut remaining = length;
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        image
            .read_exact(&mut buffer[..wanted])
            .expect("read QNX4-typed extent");
        assert!(
            buffer[..wanted].iter().all(|byte| *byte == 0),
            "the QNX4-typed extent is expected to be completely unformatted"
        );
        remaining -= u64::try_from(wanted).expect("buffer length fits u64");
    }
}

fn audit_directory(filesystem: &mut dyn TargetFilesystem, path: &str, audit: &mut Audit) {
    audit.directories += 1;
    let mut entries = filesystem
        .read_dir(path)
        .unwrap_or_else(|error| panic!("list {path}: {error}"));
    entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    for entry in entries {
        let child = child_path(path, &entry.name);
        audit.digest.update(child.as_bytes());
        audit.digest.update([u8::from(entry.metadata.is_dir)]);
        audit.digest.update(entry.metadata.size.to_le_bytes());
        if entry.metadata.is_dir {
            audit_directory(filesystem, &child, audit);
            continue;
        }

        audit.files += 1;
        audit.bytes += entry.metadata.size;
        audit.largest_file = audit.largest_file.max(entry.metadata.size);
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; 8 * 1024 * 1024];
        while offset < entry.metadata.size {
            let wanted = usize::try_from(entry.metadata.size - offset)
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let read = filesystem
                .read_at(&child, offset, &mut buffer[..wanted])
                .unwrap_or_else(|error| panic!("read {child} at {offset}: {error}"));
            assert!(read > 0, "{child} returned EOF at {offset}");
            audit.digest.update(&buffer[..read]);
            offset += u64::try_from(read).expect("read count fits u64");
        }
        let mut past_end = [0_u8; 1];
        assert_eq!(
            filesystem
                .read_at(&child, entry.metadata.size, &mut past_end)
                .unwrap_or_else(|error| panic!("read EOF of {child}: {error}")),
            0,
            "{child} must stop at its inode size"
        );
    }
}

#[test]
fn uconnect_qnx6_volumes_match_exhaustive_content_fingerprints() {
    let Some(path) = fixture() else {
        eprintln!("skipped: set FSMNT_UCONNECT_IMAGE to the Uconnect raw image");
        return;
    };
    let layout = image_layout(&path).expect("read the Uconnect MBR/EBR layout");
    assert_eq!(layout.size_bytes, 15_737_028_608);
    assert_eq!(layout.partitions.len(), 5);
    assert!(matches!(layout.kind, fsmnt::LayoutKind::Mbr));
    let expected_partitions: [(u64, u64, &str, DetectedBootSector); 5] = [
        (16_384, 2_080_768, "QNX4.x", DetectedBootSector::Unknown),
        (
            2_097_152,
            10_792_992_768,
            "QNX6 Power-Safe",
            DetectedBootSector::Qnx6,
        ),
        (
            10_795_089_920,
            3_886_022_656,
            "QNX6 Power-Safe",
            DetectedBootSector::Qnx6,
        ),
        (
            14_681_128_960,
            209_698_816,
            "QNX6 Power-Safe",
            DetectedBootSector::Qnx6,
        ),
        (
            14_890_844_160,
            846_184_448,
            "QNX6 Power-Safe",
            DetectedBootSector::Qnx6,
        ),
    ];
    for (ordinal, (offset, size, type_name, detected)) in
        expected_partitions.into_iter().enumerate()
    {
        let partition = &layout.partitions[ordinal];
        assert_eq!(partition.ordinal, Some(ordinal));
        assert_eq!(partition.offset, offset);
        assert_eq!(partition.size_bytes, size);
        assert_eq!(partition.missing_bytes, 0);
        assert_eq!(partition.type_name.as_deref(), Some(type_name));
        assert_eq!(partition.detected, Some(detected));
    }
    assert_zero_extent(
        &path,
        layout.partitions[0].offset,
        layout.partitions[0].size_bytes,
    );

    let registry = fsmnt::drivers::default_registry();
    for (ordinal, expected) in (1..=4).zip(&EXPECTED_VOLUMES) {
        let mut opened = open_image_with_options(
            &path,
            &registry,
            ImageOpenOptions::new().with_partition(ordinal),
        )
        .unwrap_or_else(|error| panic!("open QNX6 partition {ordinal}: {error}"));
        assert_eq!(opened.detected, DetectedBootSector::Qnx6);
        assert_eq!(opened.offset, layout.partitions[ordinal].offset);
        assert_eq!(opened.size_bytes, expected.total_bytes);
        assert_eq!(opened.declared_size_bytes, expected.total_bytes);
        assert_eq!(opened.truncated_by, None);
        assert_eq!(
            opened.filesystem.volume_uuid().as_deref(),
            Some(expected.uuid)
        );
        assert_eq!(opened.filesystem.total_size(), Some(expected.total_bytes));
        assert_eq!(opened.filesystem.free_space(), Some(expected.free_bytes));
        assert!(opened.filesystem.notices().is_empty());

        let root_names = opened
            .filesystem
            .read_dir("/")
            .unwrap_or_else(|error| panic!("list QNX6 partition {ordinal}: {error}"))
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(root_names, expected.root_names);

        let mut audit = Audit::default();
        audit_directory(opened.filesystem.as_mut(), "/", &mut audit);
        assert_eq!(audit.directories, expected.directories);
        assert_eq!(audit.files, expected.files);
        assert_eq!(audit.bytes, expected.logical_bytes);
        assert_eq!(audit.largest_file, expected.largest_file);
        assert_eq!(
            format!("{:x}", audit.digest.finalize()),
            expected.content_sha256
        );
    }
}
