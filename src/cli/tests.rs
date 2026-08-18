//! Unit tests for the command-line surface: argument parsing, the
//! drive-versus-image split of the `partitions` target, and the conflicts
//! clap is expected to enforce.

use clap::Parser;
use fsmnt::device::FilesystemRoot;

use crate::cli::partitions::is_image_target;
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
    assert_eq!(offset, 0);

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
    assert_eq!(offset, 32_768);
}

#[test]
fn partitions_accepts_a_drive_id_or_an_image_path() {
    for target in ["0", "sda", "disk2", "nvme0n1", "disk.bin", "/mnt/e.E01"] {
        let cli =
            Cli::try_parse_from(["fsmnt", "partitions", target]).expect("partitions target parses");
        let Commands::Partitions { target: parsed } = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(parsed, target);
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
