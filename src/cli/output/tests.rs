//! Unit tests for the reports, in both of the forms they are read in.
//!
//! The JSON tests assert the wire format itself — exact keys and values —
//! because that is the promise `--json` makes: a field that changes meaning
//! here is a schema break, and a test that only checked the Rust types would
//! never notice one. The text tests assert whole renderings, character for
//! character, for the same reason: the table is an interface too, and a
//! column that shifts is a line somebody's `awk` stops matching.

use serde_json::{Value, json};

use fsmnt::device::{DetectedBootSector, HostDriveBusType, HostDriveId, HostDriveInfo};
use fsmnt::{DriveLayout, ImageFormat, ImageLayout, LayoutKind, LayoutOrigin, LayoutPartition};

use super::{
    DrivesDocument, MountReport, MountedEvent, OpenedEvent, PartitionsDocument, Report, SourceRef,
    UnmountDocument, UnmountedEvent, VolumeEntry,
};
use crate::cli::source::Source;

/// An MBR image with two entries, the second of which the image stops
/// inside.
fn mbr_layout() -> ImageLayout {
    ImageLayout {
        format: ImageFormat::Raw,
        sector_size: 512,
        sector_size_auto_detected: false,
        origin: LayoutOrigin::Table,
        size_bytes: 32_768,
        kind: LayoutKind::Mbr,
        partitions: vec![
            LayoutPartition {
                ordinal: Some(0),
                offset: 4096,
                size_bytes: 4096,
                missing_bytes: 0,
                type_name: Some("Linux".to_string()),
                name: None,
                detected: Some(DetectedBootSector::Unknown),
                head_absent: None,
            },
            LayoutPartition {
                ordinal: Some(1),
                offset: 8192,
                size_bytes: 24_576,
                missing_bytes: 8192,
                type_name: Some("NTFS/HPFS/exFAT".to_string()),
                name: None,
                detected: Some(DetectedBootSector::Ntfs),
                head_absent: None,
            },
        ],
    }
}

/// Serialize a report, as a reader receives it.
fn value(document: &impl serde::Serialize) -> Value {
    serde_json::to_value(document).expect("a report serializes")
}

/// Render a report the way `emit` writes it to a terminal.
fn text(report: &impl Report) -> String {
    let mut rendered = Vec::new();
    report
        .render_text(&mut rendered)
        .expect("a rendering into memory cannot fail");
    String::from_utf8(rendered).expect("the rendering is UTF-8")
}

/// The expected rendering, written one printed line per element.
///
/// Every printer ends its last line, so the join carries a trailing
/// newline: a table that lost it would run into the next prompt.
fn lines(lines: &[&str]) -> String {
    format!("{}\n", lines.join("\n"))
}

#[test]
fn an_image_listing_carries_numbers_provenance_and_lowercase_filesystems() {
    let source = Source::Image("disk.bin".into());
    let document = value(&PartitionsDocument::from_image(&source, &mbr_layout()));

    assert_eq!(document["schema"], 1);
    assert_eq!(document["kind"], "partitions");
    assert_eq!(
        document["source"],
        json!({"kind": "image", "path": "disk.bin", "id": null}),
    );
    assert_eq!(document["format"], "raw");
    assert_eq!(document["model"], Value::Null);
    assert_eq!(document["size_bytes"], 32_768);
    assert_eq!(document["sector_size"], 512);
    assert_eq!(document["sector_size_auto_detected"], false);
    assert_eq!(document["table"], "mbr");
    assert_eq!(document["origin"], "table");
    assert_eq!(document["scan_stride"], Value::Null);
    assert_eq!(document["bare_filesystem"], Value::Null);

    let partitions = document["partitions"].as_array().expect("an array");
    assert_eq!(partitions.len(), 2);
    assert_eq!(
        partitions[0],
        json!({
            "ordinal": 0,
            "name": null,
            "type": "Linux",
            "offset": 4096,
            "size_bytes": 4096,
            "missing_bytes": 0,
            "available_bytes": 4096,
            "filesystem": "unknown",
            "beyond_end": false,
            "truncated": false,
            "head_absent": null,
            "volumes": null,
        }),
    );
    assert_eq!(partitions[1]["filesystem"], "ntfs");
    assert_eq!(partitions[1]["truncated"], true);
    assert_eq!(partitions[1]["missing_bytes"], 8192);
    assert_eq!(
        partitions[1]["available_bytes"], 16_384,
        "what the image carries of the extent, not what the table declares"
    );
    assert!(
        partitions[1]["size_bytes"].is_number(),
        "sizes are numbers a caller can subtract, never `24.5 KB`"
    );
}

#[test]
fn a_scanned_listing_states_its_stride_and_leaves_an_unmountable_row_unnumbered() {
    let layout = ImageLayout {
        origin: LayoutOrigin::Scan { stride: 4096 },
        kind: LayoutKind::Scanned,
        partitions: vec![
            LayoutPartition {
                ordinal: None,
                offset: 0,
                size_bytes: 4_100_000_000,
                missing_bytes: 0,
                type_name: None,
                name: None,
                detected: Some(DetectedBootSector::Ext),
                head_absent: Some(469_762_048),
            },
            LayoutPartition {
                ordinal: Some(0),
                offset: 270_532_608,
                size_bytes: 3_300_000_000,
                missing_bytes: 0,
                type_name: None,
                name: None,
                detected: Some(DetectedBootSector::Ext),
                head_absent: None,
            },
        ],
        ..mbr_layout()
    };
    let document = value(&PartitionsDocument::from_image(
        &Source::Image("vendor.img".into()),
        &layout,
    ));

    assert_eq!(document["table"], "scanned");
    assert_eq!(document["origin"], "scan");
    assert_eq!(
        document["scan_stride"], 4096,
        "a synthetic table has to say what built it"
    );

    let partitions = document["partitions"].as_array().expect("an array");
    assert_eq!(
        partitions[0]["ordinal"],
        Value::Null,
        "a row a person sees as `-` is null, not 0 and not a string"
    );
    assert_eq!(partitions[0]["head_absent"], 469_762_048_u64);
    assert_eq!(partitions[1]["ordinal"], 0);
    assert_eq!(partitions[1]["head_absent"], Value::Null);
}

#[test]
fn a_bare_medium_names_the_filesystem_that_fills_it() {
    let layout = ImageLayout {
        kind: LayoutKind::Bare(DetectedBootSector::BitLocker),
        origin: LayoutOrigin::None,
        partitions: Vec::new(),
        ..mbr_layout()
    };
    let document = value(&PartitionsDocument::from_image(
        &Source::Image("bde.img".into()),
        &layout,
    ));

    assert_eq!(document["table"], "bare");
    assert_eq!(document["origin"], "none");
    assert_eq!(
        document["bare_filesystem"], "bitlocker",
        "one token per format on the wire, whatever the mount labels it"
    );
}

/// A GPT drive read from its backup header, whose second entry is bounded
/// by nothing and carries no filesystem.
fn gpt_layout() -> DriveLayout {
    DriveLayout {
        sector_size: 512,
        sector_size_auto_detected: false,
        origin: LayoutOrigin::BackupTable,
        size_bytes: 2_000_398_934_016,
        kind: LayoutKind::Gpt,
        partitions: vec![
            LayoutPartition {
                ordinal: Some(0),
                offset: 1_048_576,
                size_bytes: 104_857_600,
                missing_bytes: 0,
                type_name: Some("EFI System".to_string()),
                name: Some("EFI system partition".to_string()),
                detected: Some(DetectedBootSector::Fat32),
                head_absent: None,
            },
            LayoutPartition {
                ordinal: Some(1),
                offset: 316_669_952,
                size_bytes: 0,
                missing_bytes: 0,
                type_name: None,
                name: None,
                detected: None,
                head_absent: None,
            },
        ],
    }
}

/// That drive's listing: one partition with a volume over it, and one whose
/// volumes could not be resolved.
fn gpt_document() -> PartitionsDocument {
    PartitionsDocument::from_drive(
        &Source::Drive(HostDriveId::new("0")),
        Some("Samsung SSD 990 PRO 2TB".to_string()),
        &gpt_layout(),
        |partition| {
            (partition.offset == 1_048_576).then(|| {
                vec![VolumeEntry {
                    id: "volume-5f2".to_string(),
                    mount_points: vec!["C:".to_string()],
                }]
            })
        },
    )
}

#[test]
fn a_drive_listing_carries_its_model_and_the_volumes_over_each_partition() {
    let document = value(&gpt_document());

    assert_eq!(
        document["source"],
        json!({"kind": "drive", "path": null, "id": "0"}),
    );
    assert_eq!(document["format"], Value::Null, "a drive has no container");
    assert_eq!(document["model"], "Samsung SSD 990 PRO 2TB");
    assert_eq!(document["table"], "gpt");
    assert_eq!(
        document["origin"], "backup_table",
        "where the entries came from is part of the answer, not a footnote"
    );

    let partitions = document["partitions"].as_array().expect("an array");
    assert_eq!(partitions[0]["name"], "EFI system partition");
    assert_eq!(partitions[0]["type"], "EFI System");
    assert_eq!(partitions[0]["filesystem"], "fat32");
    assert_eq!(
        partitions[0]["volumes"],
        json!([{"id": "volume-5f2", "mount_points": ["C:"]}]),
    );
    assert_eq!(
        partitions[1]["size_bytes"],
        Value::Null,
        "an extent bounded by nothing has no length to report"
    );
    assert_eq!(partitions[1]["available_bytes"], Value::Null);
    assert_eq!(
        partitions[1]["beyond_end"], false,
        "a length nobody established cannot put the extent past the end"
    );
    assert_eq!(partitions[1]["filesystem"], Value::Null);
    assert_eq!(
        partitions[1]["volumes"],
        Value::Null,
        "volume discovery that could not run is unknown, not empty"
    );
}

/// Two drives: one this process can read, one it was refused.
fn drives_document() -> DrivesDocument {
    let mut readable = HostDriveInfo::new(HostDriveId::new("0"), "/dev/nvme0n1".into());
    readable.size_bytes = Some(2_000_398_934_016);
    readable.sector_size = Some(512);
    readable.model = Some("Samsung SSD 990 PRO 2TB".to_string());
    readable.serial_number = Some("S7DNNJ0X".to_string());
    readable.bus_type = Some(HostDriveBusType::Nvme);
    readable.removable = Some(false);
    readable.accessible = true;

    let mut denied = HostDriveInfo::new(HostDriveId::new("1"), "/dev/sdb".into());
    denied.bus_type = Some(HostDriveBusType::Usb);
    denied.access_error = Some("access is denied".to_string());

    DrivesDocument::new(&[readable, denied])
}

#[test]
fn the_drives_document_reports_what_each_drive_says_about_itself() {
    let document = value(&drives_document());

    assert_eq!(document["schema"], 1);
    assert_eq!(document["kind"], "drives");
    let drives = document["drives"].as_array().expect("an array");
    assert_eq!(
        drives[0],
        json!({
            "id": "0",
            "path": "/dev/nvme0n1",
            "size_bytes": 2_000_398_934_016_u64,
            "sector_size": 512,
            "model": "Samsung SSD 990 PRO 2TB",
            "serial_number": "S7DNNJ0X",
            "bus": "nvme",
            "removable": false,
            "accessible": true,
            "access_error": null,
        }),
    );
    assert_eq!(
        drives[1]["bus"], "usb",
        "the bus is the display name a person reads, lowercased"
    );
    assert_eq!(drives[1]["size_bytes"], Value::Null);
    assert_eq!(drives[1]["accessible"], false);
    assert_eq!(drives[1]["access_error"], "access is denied");
}

#[test]
fn an_unmount_is_one_document() {
    assert_eq!(
        value(&UnmountDocument::new("Z:")),
        json!({"schema": 1, "kind": "unmount", "mountpoint": "Z:", "unmounted": true}),
    );
}

#[test]
fn an_image_listing_prints_the_same_facts_as_a_table() {
    let source = Source::Image("disk.bin".into());
    assert_eq!(
        text(&PartitionsDocument::from_image(&source, &mbr_layout())),
        lines(&[
            "disk.bin: raw image, 0 MB, sector size 512",
            "MBR partition table",
            "   #  TYPE                    SIZE         OFFSET  FILESYSTEM",
            "   0  Linux                   0 MB           4096  Unknown",
            "   1  NTFS/HPFS/exFAT         0 MB           8192  Ntfs  TRUNCATED (0 MB missing)",
            "",
            "Mount one with: fsmnt mount disk.bin <MOUNTPOINT> --partition <#>",
        ]),
    );
}

#[test]
fn a_drive_listing_prints_the_volume_column_an_image_has_no_use_for() {
    assert_eq!(
        text(&gpt_document()),
        lines(&[
            "0: drive (Samsung SSD 990 PRO 2TB), 2000.3 GB, sector size 512",
            "GPT partition table (recovered from the backup header in the last sector; the \
             primary header at the front of the drive is damaged)",
            "   #  NAME                  TYPE               SIZE         OFFSET  FILESYSTEM  \
             VOLUME",
            "   0  EFI system partition  EFI System       104 MB        1048576  Fat32       \
             volume-5f2 (C:)",
            "   1  -                     Unknown         unknown      316669952  unreadable  -",
            "",
            "Mount one with: fsmnt mount 0 <MOUNTPOINT> --partition <#>",
        ]),
        "the drive ID, the provenance of the table and the volumes are all read off the document"
    );
}

#[test]
fn the_drives_table_says_why_a_drive_could_not_be_read() {
    assert_eq!(
        text(&drives_document()),
        lines(&[
            "ID                 SIZE  BUS        MODEL                        ACCESS",
            "0             2000.3 GB  NVMe       Samsung SSD 990 PRO 2TB      ok",
            "1               unknown  USB        -                            inaccessible \
             (access is denied)",
        ]),
    );
    assert_eq!(
        text(&DrivesDocument::new(&[])),
        "No drives found.\n",
        "an empty list is an answer, not an empty table"
    );
}

#[test]
fn an_unmount_names_the_mountpoint_it_released() {
    assert_eq!(text(&UnmountDocument::new("Z:")), "Unmounted Z:.\n");
}

#[test]
fn a_mounted_volume_says_who_is_holding_it_to_both_audiences() {
    assert_eq!(
        text(&MountedEvent::foreground("Z:", 76_532)),
        "Volume mounted at Z:. Press Ctrl+C, or run 'fsmnt unmount Z:' from another shell, to \
         unmount.\n",
    );
    assert_eq!(
        text(&MountedEvent::detached("Z:", 76_532)),
        "Volume mounted at Z: (pid 76532); run 'fsmnt unmount Z:' to unmount.\n",
        "a detached mount is held by a process this command is about to outlive"
    );

    assert_eq!(
        value(&MountedEvent::foreground("Z:", 76_532)),
        json!({
            "schema": 1,
            "event": "mounted",
            "mountpoint": "Z:",
            "pid": 76_532,
            "detached": false,
        }),
    );
    assert_eq!(
        value(&MountedEvent::detached("/mnt/evidence", 4021))["detached"],
        true,
        "the field a reader needs to know whose pid it just got"
    );
}

#[test]
fn the_end_of_a_mount_is_one_word_and_one_event() {
    assert_eq!(text(&UnmountedEvent::new("Z:", None)), "Unmounted.\n");
    assert_eq!(
        value(&UnmountedEvent::new("Z:", None)),
        json!({"schema": 1, "event": "unmounted", "mountpoint": "Z:", "best_effort": null}),
    );
}

#[test]
fn the_opened_event_prints_nothing_because_the_log_has_already_said_it() {
    let report = MountReport {
        source: SourceRef::new(&Source::Image("disk.bin".into())),
        filesystem: "ntfs",
        volname: "disk".to_string(),
        fsname: "ntfs".to_string(),
        offset: Some(8192),
        partition: Some(1),
        size_bytes: Some(24_576),
        layout_origin: Some(LayoutOrigin::Table),
        truncated_by: None,
        head_absent: None,
    };
    let notices = vec!["opened through the backup superblock in group 1".to_string()];

    assert_eq!(
        text(&OpenedEvent::new(&report, notices.clone())),
        "",
        "its facts reached a person as the info and warn lines that precede it"
    );
    assert_eq!(
        value(&OpenedEvent::new(&report, notices))["notices"],
        json!(["opened through the backup superblock in group 1"]),
        "which is exactly why the wire form repeats them"
    );
}
