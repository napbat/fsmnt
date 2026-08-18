//! Unit tests for the command-line surface: argument parsing, the
//! drive-versus-image split of the `partitions` target, and the conflicts
//! clap is expected to enforce.

use clap::Parser;
use fsmnt::device::FilesystemRoot;

use crate::cli::partitions::is_image_target;
use crate::cli::size::SizeExpr;
use crate::{Cli, Commands, FilesystemMountOptions};

#[test]
fn image_partition_is_parsed_and_defaults_to_none() {
    let cli = Cli::try_parse_from(["fsmnt", "mount-image", "disk.bin", "Z:", "--partition", "3"])
        .expect("image partition");
    let Commands::MountImage {
        partition, offset, ..
    } = cli.command
    else {
        panic!("wrong command");
    };
    assert_eq!(partition, Some(3));
    assert_eq!(offset, SizeExpr::Bytes(0));

    let cli =
        Cli::try_parse_from(["fsmnt", "mount-image", "disk.bin", "Z:"]).expect("plain image mount");
    let Commands::MountImage { partition, .. } = cli.command else {
        panic!("wrong command");
    };
    assert_eq!(partition, None);
}

#[test]
fn image_partition_and_offset_are_mutually_exclusive() {
    let result = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "disk.bin",
        "Z:",
        "--partition",
        "3",
        "--offset",
        "1048576",
    ]);
    assert!(result.is_err());
}

#[test]
fn image_offset_still_works_on_its_own() {
    let cli = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "disk.bin",
        "Z:",
        "--offset",
        "32768",
    ])
    .expect("image offset");
    let Commands::MountImage {
        partition, offset, ..
    } = cli.command
    else {
        panic!("wrong command");
    };
    assert_eq!(partition, None);
    assert_eq!(offset, SizeExpr::Bytes(32_768));
}

#[test]
fn image_offset_accepts_size_suffixes_and_sector_counts() {
    for (argument, expected) in [
        ("270532608", SizeExpr::Bytes(270_532_608)),
        ("258MiB", SizeExpr::Bytes(270_532_608)),
        ("1M", SizeExpr::Bytes(1_048_576)),
        ("528384s", SizeExpr::Sectors(528_384)),
    ] {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-image",
            "disk.bin",
            "Z:",
            "--offset",
            argument,
        ])
        .expect("size expression");
        let Commands::MountImage { offset, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(offset, expected, "--offset {argument}");
    }

    let result = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "disk.bin",
        "Z:",
        "--offset",
        "258 flurbs",
    ]);
    assert!(result.is_err(), "an unknown unit is rejected by clap");
}

#[test]
fn a_sector_count_offset_is_resolved_against_the_sector_size() {
    let cli = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "disk.bin",
        "Z:",
        "--offset",
        "4096s",
        "--sector-size",
        "65536",
    ])
    .expect("sector offset");
    let Commands::MountImage {
        offset,
        sector_size,
        ..
    } = cli.command
    else {
        panic!("wrong command");
    };
    assert_eq!(sector_size, Some(65_536));
    assert_eq!(offset.resolve(65_536), Ok(268_435_456));
}

#[test]
fn sector_sizes_are_validated_by_clap() {
    for command in [
        vec![
            "fsmnt",
            "mount-image",
            "disk.bin",
            "Z:",
            "--sector-size",
            "4096",
        ],
        vec!["fsmnt", "partitions", "disk.bin", "--sector-size", "4096"],
        vec!["fsmnt", "scan", "disk.bin", "--sector-size", "4096"],
    ] {
        assert!(
            Cli::try_parse_from(&command).is_ok(),
            "4096 is a valid sector size for {command:?}"
        );
    }
    for bad in ["0", "256", "1000", "notanumber"] {
        let result = Cli::try_parse_from(["fsmnt", "partitions", "disk.bin", "--sector-size", bad]);
        assert!(result.is_err(), "--sector-size {bad} should be rejected");
    }
}

#[test]
fn scan_takes_an_image_and_optional_stride() {
    let cli = Cli::try_parse_from(["fsmnt", "scan", "disk.bin"]).expect("scan defaults");
    let Commands::Scan {
        image,
        stride,
        sector_size,
    } = cli.command
    else {
        panic!("wrong command");
    };
    assert_eq!(image.to_string_lossy(), "disk.bin");
    assert_eq!(stride, fsmnt::DEFAULT_STRIDE);
    assert_eq!(sector_size, None);

    let cli = Cli::try_parse_from(["fsmnt", "scan", "disk.bin", "--stride", "512"])
        .expect("scan with a finer stride");
    let Commands::Scan { stride, .. } = cli.command else {
        panic!("wrong command");
    };
    assert_eq!(stride, 512);
}

#[test]
fn partitions_accepts_a_drive_id_or_an_image_path() {
    for target in ["0", "sda", "disk2", "nvme0n1", "disk.bin", "/mnt/e.E01"] {
        let cli =
            Cli::try_parse_from(["fsmnt", "partitions", target]).expect("partitions target parses");
        let Commands::Partitions {
            target: parsed,
            sector_size,
            ..
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert_eq!(parsed, target);
        assert_eq!(sector_size, None);
    }
}

#[test]
fn drive_ids_are_not_mistaken_for_image_paths() {
    for drive in ["0", "1", "sda", "sdb1", "disk2", "nvme0n1"] {
        assert!(!is_image_target(drive), "{drive} should be a drive ID");
    }
}

#[test]
fn image_paths_are_recognized_by_separator_or_extension() {
    for image in [
        "disk.bin",
        "evidence.E01",
        "sub/dir/raw",
        r"C:\images\win11.vhdx",
        "./image",
    ] {
        assert!(is_image_target(image), "{image} should be an image path");
    }
}

#[test]
fn an_existing_extensionless_file_is_treated_as_an_image() {
    let dir = tempfile::tempdir().expect("temp dir");
    let file = dir.path().join("rawdump");
    std::fs::write(&file, b"not a disk").expect("write fixture");
    assert!(is_image_target(&file.to_string_lossy()));
    assert!(!is_image_target("rawdump"), "no such file in the cwd");
}

#[test]
fn filesystem_root_supports_cross_format_selectors() {
    for (selector, expected) in [
        ("default", FilesystemRoot::Default),
        ("top-level", FilesystemRoot::TopLevel),
        ("id:256", FilesystemRoot::Id(256)),
        ("index:2", FilesystemRoot::Index(2)),
        (
            "name:Macintosh HD - Data",
            FilesystemRoot::Name("Macintosh HD - Data".to_string()),
        ),
        ("role:data", FilesystemRoot::Role("data".to_string())),
    ] {
        let cli =
            Cli::try_parse_from(["fsmnt", "mount-image", "image", "Z:", "--fs-root", selector])
                .expect("filesystem root selector");
        let Commands::MountImage { filesystem, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(filesystem.root(), expected);
    }
}

#[test]
fn default_filesystem_root_is_typed() {
    assert_eq!(
        FilesystemMountOptions::default().root(),
        FilesystemRoot::Default
    );
}

#[test]
fn unmount_is_also_spelled_umount() {
    for name in ["unmount", "umount"] {
        let cli = Cli::try_parse_from(["fsmnt", name, "Z:"]).expect("unmount command");
        let Commands::Unmount { mountpoint } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(mountpoint, "Z:");
    }
}

#[test]
fn every_mount_command_can_detach() {
    let commands: &[&[&str]] = &[
        &["fsmnt", "mount", "source", "Z:", "--detach"],
        &["fsmnt", "mount-image", "image", "Z:", "--detach"],
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        &["fsmnt", "mount-device", "0", "Z:", "--detach"],
    ];
    for args in commands {
        let cli = Cli::try_parse_from(*args).expect("detached mount");
        assert_eq!(cli.command.detached_mountpoint(), Some("Z:"));
    }
}

#[test]
fn mounts_stay_in_the_foreground_without_the_detach_flag() {
    let cli = Cli::try_parse_from(["fsmnt", "mount-image", "image", "Z:"]).expect("mount");
    assert_eq!(cli.command.detached_mountpoint(), None);

    let cli = Cli::try_parse_from(["fsmnt", "unmount", "Z:"]).expect("unmount");
    assert_eq!(cli.command.detached_mountpoint(), None);
}

#[test]
fn journal_replay_is_on_unless_declined() {
    let cli = Cli::try_parse_from(["fsmnt", "mount-image", "image", "Z:"]).expect("default mount");
    let Commands::MountImage { filesystem, .. } = cli.command else {
        panic!("wrong command");
    };
    assert!(filesystem.open_options().journal_replay());
    assert_eq!(
        filesystem.open_options(),
        fsmnt::device::FilesystemOpenOptions::new(),
        "defaults must round-trip to the driver defaults"
    );

    let cli = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "image",
        "Z:",
        "--no-journal-replay",
        "--fs-root",
        "role:data",
    ])
    .expect("mount without replay");
    let Commands::MountImage { filesystem, .. } = cli.command else {
        panic!("wrong command");
    };
    let options = filesystem.open_options();
    assert!(!options.journal_replay());
    assert_eq!(options.root(), &FilesystemRoot::Role("data".to_string()));
}

#[test]
fn malformed_filesystem_root_is_rejected_by_clap() {
    let result = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "image",
        "Z:",
        "--fs-root",
        "subvolume-without-a-selector-kind",
    ]);
    assert!(result.is_err());
}

/// Tests for the device commands, which only exist on platforms with a
/// drive enumerator.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod device {
    use super::{Cli, Commands, FilesystemRoot, Parser};
    use crate::cli::mount::parse_partition_address;

    #[test]
    fn raw_member_address_uses_last_colon() {
        let address = parse_partition_address("device:name:3").expect("partition address");
        assert_eq!(address.drive().as_str(), "device:name");
        assert_eq!(address.partition(), 3);
    }

    #[test]
    fn raw_member_requires_raw_flag() {
        let result = Cli::try_parse_from(["fsmnt", "mount-device", "0", "Z:", "--member", "1:0"]);
        assert!(result.is_err());
    }

    #[test]
    fn raw_and_logical_volume_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "0",
            "Z:",
            "--raw",
            "--volume",
            "logical-id",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn filesystem_root_is_parsed_for_device_mounts() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "0",
            "Z:",
            "--raw",
            "--fs-root",
            "path:root/snapshot",
        ])
        .expect("filesystem root path");
        let Commands::MountDevice { filesystem, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(
            filesystem.root(),
            FilesystemRoot::Path("root/snapshot".to_string())
        );
    }

    #[test]
    fn fstab_flag_defaults_to_the_selected_roots_table() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "1",
            "Z:",
            "--raw",
            "--fstab",
            "--fs-root",
            "path:root",
        ])
        .expect("fstab mount");
        let Commands::MountDevice { fstab, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(fstab.as_deref(), Some("/etc/fstab"));
    }

    #[test]
    fn fstab_flag_accepts_a_custom_guest_path() {
        let cli = Cli::try_parse_from([
            "fsmnt",
            "mount-device",
            "1",
            "Z:",
            "--fstab",
            "/etc/fstab.forensic",
        ])
        .expect("custom fstab mount");
        let Commands::MountDevice { fstab, .. } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(fstab.as_deref(), Some("/etc/fstab.forensic"));
    }
}

#[test]
fn scan_ordinals_require_partition_and_exclude_offset() {
    let cli = Cli::try_parse_from([
        "fsmnt",
        "mount-image",
        "disk.bin",
        "Z:",
        "--scan",
        "--partition",
        "2",
        "--stride",
        "512",
    ])
    .expect("mount by synthetic ordinal");
    let Commands::MountImage {
        scan,
        stride,
        partition,
        ..
    } = cli.command
    else {
        panic!("wrong command");
    };
    assert!(scan);
    assert_eq!(stride, 512);
    assert_eq!(partition, Some(2));

    assert!(
        Cli::try_parse_from(["fsmnt", "mount-image", "disk.bin", "Z:", "--scan"]).is_err(),
        "--scan without --partition has nothing to resolve"
    );
    assert!(
        Cli::try_parse_from([
            "fsmnt",
            "mount-image",
            "disk.bin",
            "Z:",
            "--scan",
            "--partition",
            "0",
            "--offset",
            "4096",
        ])
        .is_err(),
        "--scan and --offset are different ways of saying where"
    );
    assert!(
        Cli::try_parse_from(["fsmnt", "mount-image", "disk.bin", "Z:", "--stride", "512"]).is_err(),
        "--stride only means something for --scan"
    );

    let cli = Cli::try_parse_from([
        "fsmnt",
        "partitions",
        "disk.bin",
        "--scan",
        "--stride",
        "512",
    ])
    .expect("synthetic listing");
    let Commands::Partitions { scan, stride, .. } = cli.command else {
        panic!("wrong command");
    };
    assert!(scan);
    assert_eq!(stride, 512);
}
