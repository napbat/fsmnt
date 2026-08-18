//! Unit tests for the command-line surface: the shape of the argument
//! tree, the conflicts clap is expected to enforce, and the applicability
//! rules that only make sense once the source has been resolved.

use clap::Parser;
use fsmnt::device::FilesystemRoot;

use crate::cli::mount::check_options;
use crate::cli::size::SizeExpr;
use crate::cli::source::{Source, SourceKind, resolve};
use crate::{Cli, Commands, FilesystemMountOptions, MountArgs};

/// Parse a command line that is expected to be a `mount`.
fn mount(command_line: &[&str]) -> MountArgs {
    let parsed = Cli::try_parse_from(command_line).expect("mount command");
    let Commands::Mount(mounted) = parsed.command else {
        panic!("{command_line:?} did not parse as a mount");
    };
    *mounted
}

#[test]
fn mount_takes_one_source_of_any_kind() {
    let dir = tempfile::tempdir().expect("temp dir");
    let directory = dir.path().to_string_lossy().into_owned();
    let cases: [(&str, Source); 3] = [
        (
            directory.as_str(),
            Source::Directory(dir.path().to_path_buf()),
        ),
        ("disk.bin", Source::Image("disk.bin".into())),
        ("0", Source::Drive(fsmnt::device::HostDriveId::new("0"))),
    ];
    for (text, expected) in cases {
        let args = mount(&["fsmnt", "mount", text, "Z:"]);
        assert_eq!(args.source, text);
        assert_eq!(args.mountpoint, "Z:");
        assert_eq!(
            resolve(&args.source, args.source_kind()).expect("resolved source"),
            expected
        );
    }
}

#[test]
fn one_mount_command_replaces_the_three_that_split_by_source_kind() {
    let args = mount(&["fsmnt", "mount", "disk.bin", "Z:", "--partition", "2"]);
    assert_eq!(args.partition, Some(2));
    for gone in ["mount-image", "mount-device"] {
        assert!(
            Cli::try_parse_from(["fsmnt", gone, "disk.bin", "Z:"]).is_err(),
            "{gone} is not a command any more"
        );
    }
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
fn logging_flags_are_accepted_on_either_side_of_the_subcommand() {
    for argv in [
        ["fsmnt", "-v", "partitions", "disk.bin"],
        ["fsmnt", "partitions", "disk.bin", "-v"],
    ] {
        let cli = Cli::try_parse_from(argv).expect("global verbosity");
        assert_eq!(cli.log.verbose, 1, "{argv:?}");
        assert!(!cli.log.quiet);
    }

    let cli = Cli::try_parse_from(["fsmnt", "scan", "disk.bin", "-vv"]).expect("twice as verbose");
    assert_eq!(cli.log.verbose, 2);

    let cli = Cli::try_parse_from(["fsmnt", "-q", "drives"]).expect("quiet");
    assert!(cli.log.quiet);

    let cli = Cli::try_parse_from(["fsmnt", "mount", "d", "Z:", "--log-file", "run.log"])
        .expect("log file");
    assert_eq!(
        cli.log.log_file.as_deref(),
        Some(std::path::Path::new("run.log"))
    );

    assert!(
        Cli::try_parse_from(["fsmnt", "-q", "-v", "drives"]).is_err(),
        "saying less and saying more are contradictory"
    );
}

#[test]
fn a_location_is_stated_once() {
    assert!(
        Cli::try_parse_from([
            "fsmnt",
            "mount",
            "disk.bin",
            "Z:",
            "--partition",
            "3",
            "--offset",
            "1048576",
        ])
        .is_err(),
        "--partition and --offset are two answers to the same question"
    );

    let args = mount(&["fsmnt", "mount", "disk.bin", "Z:", "--offset", "32768"]);
    assert_eq!(args.partition, None);
    assert_eq!(args.offset, Some(SizeExpr::Bytes(32_768)));

    let args = mount(&["fsmnt", "mount", "disk.bin", "Z:"]);
    assert_eq!(args.partition, None);
    assert_eq!(
        args.offset, None,
        "an unstated location is not the same as offset 0"
    );
}

#[test]
fn scan_ordinals_require_a_partition_and_a_stride_requires_a_scan() {
    let args = mount(&[
        "fsmnt",
        "mount",
        "disk.bin",
        "Z:",
        "--scan",
        "--partition",
        "2",
        "--stride",
        "512",
    ]);
    assert!(args.scan);
    assert_eq!(args.stride, 512);
    assert_eq!(args.partition, Some(2));

    assert!(
        Cli::try_parse_from(["fsmnt", "mount", "disk.bin", "Z:", "--scan"]).is_err(),
        "--scan without --partition has nothing to resolve"
    );
    assert!(
        Cli::try_parse_from([
            "fsmnt",
            "mount",
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
        Cli::try_parse_from(["fsmnt", "mount", "disk.bin", "Z:", "--stride", "512"]).is_err(),
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
    let Commands::Partitions(args) = cli.command else {
        panic!("wrong command");
    };
    assert!(args.scan);
    assert_eq!(args.stride, 512);
}

#[test]
fn a_logical_volume_excludes_every_way_of_bypassing_it() {
    for conflicting in [
        vec!["--raw"],
        vec!["--offset", "4096"],
        vec!["--scan", "--partition", "1"],
    ] {
        let mut argv = vec!["fsmnt", "mount", "0", "Z:", "--volume", "logical-id"];
        argv.extend(conflicting.iter());
        assert!(
            Cli::try_parse_from(&argv).is_err(),
            "{argv:?} should be refused"
        );
    }

    let args = mount(&["fsmnt", "mount", "0", "Z:", "--volume", "logical-id"]);
    assert_eq!(args.volume.as_deref(), Some("logical-id"));
}

#[test]
fn raw_members_are_only_meaningful_with_raw() {
    assert!(
        Cli::try_parse_from(["fsmnt", "mount", "0", "Z:", "--member", "1:0"]).is_err(),
        "--member describes an extra member of a raw source"
    );
    let args = mount(&[
        "fsmnt", "mount", "0", "Z:", "--raw", "--member", "1:0", "--member", "2:1",
    ]);
    assert_eq!(args.member, ["1:0", "2:1"]);
}

#[test]
fn fstab_defaults_to_the_guests_own_table_but_takes_a_path() {
    let args = mount(&["fsmnt", "mount", "0", "Z:", "--raw", "--fstab"]);
    assert_eq!(args.fstab.as_deref(), Some("/etc/fstab"));

    let args = mount(&[
        "fsmnt",
        "mount",
        "disk.vhdx",
        "Z:",
        "--fstab",
        "/etc/fstab.forensic",
    ]);
    assert_eq!(args.fstab.as_deref(), Some("/etc/fstab.forensic"));

    let args = mount(&["fsmnt", "mount", "disk.vhdx", "Z:"]);
    assert_eq!(args.fstab, None);
}

#[test]
fn offsets_accept_size_suffixes_and_sector_counts() {
    for (argument, expected) in [
        ("270532608", SizeExpr::Bytes(270_532_608)),
        ("258MiB", SizeExpr::Bytes(270_532_608)),
        ("1M", SizeExpr::Bytes(1_048_576)),
        ("528384s", SizeExpr::Sectors(528_384)),
    ] {
        let args = mount(&["fsmnt", "mount", "disk.bin", "Z:", "--offset", argument]);
        assert_eq!(args.offset, Some(expected), "--offset {argument}");
    }

    assert!(
        Cli::try_parse_from(["fsmnt", "mount", "disk.bin", "Z:", "--offset", "258 flurbs"])
            .is_err(),
        "an unknown unit is rejected by clap"
    );
}

#[test]
fn a_sector_count_offset_is_resolved_against_the_sector_size() {
    let args = mount(&[
        "fsmnt",
        "mount",
        "disk.bin",
        "Z:",
        "--offset",
        "4096s",
        "--sector-size",
        "65536",
    ]);
    assert_eq!(args.sector_size, Some(65_536));
    assert_eq!(
        args.offset.expect("offset").resolve(65_536),
        Ok(268_435_456)
    );
}

#[test]
fn sector_sizes_are_validated_by_clap() {
    for command in [
        vec!["fsmnt", "mount", "disk.bin", "Z:", "--sector-size", "4096"],
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
fn scan_takes_a_source_and_an_optional_stride() {
    let cli = Cli::try_parse_from(["fsmnt", "scan", "disk.bin"]).expect("scan defaults");
    let Commands::Scan(args) = cli.command else {
        panic!("wrong command");
    };
    assert_eq!(args.source, "disk.bin");
    assert_eq!(args.stride, fsmnt::DEFAULT_STRIDE);
    assert_eq!(args.sector_size, None);

    let cli = Cli::try_parse_from(["fsmnt", "scan", "0", "--stride", "512"])
        .expect("scan a drive with a finer stride");
    let Commands::Scan(args) = cli.command else {
        panic!("wrong command");
    };
    assert_eq!(args.stride, 512);
    assert_eq!(
        resolve(&args.source, args.source_kind()).expect("drive"),
        Source::Drive(fsmnt::device::HostDriveId::new("0"))
    );
}

#[test]
fn the_source_kind_overrides_are_mutually_exclusive() {
    for argv in [
        vec!["fsmnt", "mount", "x", "Z:", "--image", "--drive"],
        vec!["fsmnt", "mount", "x", "Z:", "--dir", "--image"],
        vec!["fsmnt", "mount", "x", "Z:", "--dir", "--drive"],
        vec!["fsmnt", "partitions", "x", "--image", "--drive"],
        vec!["fsmnt", "scan", "x", "--image", "--drive"],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_err(),
            "{argv:?} names two kinds of source"
        );
    }

    let args = mount(&["fsmnt", "mount", "sda", "Z:", "--image"]);
    assert_eq!(args.source_kind(), SourceKind::Image);
    assert_eq!(
        resolve(&args.source, args.source_kind()).expect("forced image"),
        Source::Image("sda".into())
    );
}

#[test]
fn only_mount_can_expose_a_host_directory() {
    for argv in [
        vec!["fsmnt", "partitions", "export", "--dir"],
        vec!["fsmnt", "scan", "export", "--dir"],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_err(),
            "{argv:?} has no directory to inspect"
        );
    }
    assert!(
        Cli::try_parse_from(["fsmnt", "mount", "export", "Z:", "--dir"]).is_ok(),
        "mount is where a directory is a source"
    );
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
        let args = mount(&["fsmnt", "mount", "image.bin", "Z:", "--fs-root", selector]);
        assert_eq!(args.filesystem.root(), expected);
    }

    assert!(
        Cli::try_parse_from([
            "fsmnt",
            "mount",
            "image.bin",
            "Z:",
            "--fs-root",
            "subvolume-without-a-selector-kind",
        ])
        .is_err(),
        "a selector with no kind is rejected by clap"
    );
}

#[test]
fn default_filesystem_root_is_typed() {
    assert_eq!(
        FilesystemMountOptions::default().root(),
        FilesystemRoot::Default
    );
}

#[test]
fn journal_replay_is_on_unless_declined() {
    let args = mount(&["fsmnt", "mount", "image.bin", "Z:"]);
    assert!(args.filesystem.open_options().journal_replay());
    assert_eq!(
        args.filesystem.open_options(),
        fsmnt::device::FilesystemOpenOptions::new(),
        "defaults must round-trip to the driver defaults"
    );

    let args = mount(&[
        "fsmnt",
        "mount",
        "image.bin",
        "Z:",
        "--no-journal-replay",
        "--fs-root",
        "role:data",
    ]);
    let options = args.filesystem.open_options();
    assert!(!options.journal_replay());
    assert_eq!(options.root(), &FilesystemRoot::Role("data".to_string()));
}

#[test]
fn every_mount_can_detach_and_nothing_else_can() {
    let cli = Cli::try_parse_from(["fsmnt", "mount", "source", "Z:", "--detach"])
        .expect("detached mount");
    assert_eq!(cli.command.detached_mountpoint(), Some("Z:"));

    let cli = Cli::try_parse_from(["fsmnt", "mount", "image", "Z:"]).expect("mount");
    assert_eq!(cli.command.detached_mountpoint(), None);

    let cli = Cli::try_parse_from(["fsmnt", "unmount", "Z:"]).expect("unmount");
    assert_eq!(cli.command.detached_mountpoint(), None);
}

#[test]
fn a_drive_option_is_refused_for_an_image_source() {
    let args = mount(&["fsmnt", "mount", "disk.bin", "Z:", "--raw"]);
    let source = resolve(&args.source, args.source_kind()).expect("image source");
    let error = check_options(&args, &source).expect_err("--raw on an image");
    assert_eq!(
        error.to_string(),
        "--raw applies to drives; disk.bin is a disk image"
    );
}

#[test]
fn a_media_option_is_refused_for_a_directory_source() {
    let dir = tempfile::tempdir().expect("temp dir");
    let text = dir.path().to_string_lossy().into_owned();
    let args = mount(&["fsmnt", "mount", &text, "Z:", "--partition", "1"]);
    let source = resolve(&args.source, args.source_kind()).expect("directory source");
    let error = check_options(&args, &source).expect_err("--partition on a directory");
    let message = error.to_string();
    assert!(
        message.starts_with("--partition applies to disk images and drives; "),
        "{message}"
    );
    assert!(message.ends_with(" is a directory"), "{message}");
}

#[test]
fn an_option_that_applies_is_left_alone() {
    let args = mount(&[
        "fsmnt",
        "mount",
        "0",
        "Z:",
        "--raw",
        "--partition",
        "1",
        "--best-effort-reads",
    ]);
    let source = resolve(&args.source, args.source_kind()).expect("drive source");
    check_options(&args, &source).expect("every option applies to a drive");

    let args = mount(&["fsmnt", "mount", "disk.bin", "Z:", "--volname", "Evidence"]);
    let source = resolve(&args.source, args.source_kind()).expect("image source");
    check_options(&args, &source).expect("--volname applies everywhere");
}

/// Tests for the raw-member syntax, which only exists on platforms with a
/// drive enumerator.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod device {
    use crate::cli::mount::parse_partition_address;

    #[test]
    fn raw_member_address_uses_last_colon() {
        let address = parse_partition_address("device:name:3").expect("partition address");
        assert_eq!(address.drive().as_str(), "device:name");
        assert_eq!(address.partition(), 3);
    }

    #[test]
    fn a_raw_member_without_an_ordinal_is_rejected() {
        assert!(parse_partition_address("0").is_err());
        assert!(parse_partition_address(":1").is_err());
        assert!(parse_partition_address("0:x").is_err());
    }
}
