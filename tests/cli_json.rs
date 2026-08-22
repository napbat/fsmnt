//! End-to-end coverage of `--json` and of the tables it replaces, by
//! running the built binary.
//!
//! The two-stream contract is a property of a whole process — stdout carries
//! JSON and nothing else, stderr carries one JSON object per event, and the
//! exit code is unchanged — so it cannot be checked from a unit test that
//! calls a handler. These run `fsmnt` itself over a temporary MBR image and
//! parse what comes back, exactly as a driving program would.
//!
//! Each JSON test has a twin without the flag, because the two renderings
//! come from one report: a change that reaches the document reaches the
//! table, and both are read by somebody.

use std::process::{Command, Output};

use fsmnt_testkit::write_mbr_partition_entry as write_mbr_entry;
use serde_json::Value;

/// Sector size of the synthetic media.
const SECTOR_SIZE: usize = 512;

/// Length of the synthetic media.
const MEDIA_SIZE: usize = 32_768;

/// LBA of the leading data partition, which holds no filesystem.
const DATA_START_LBA: u32 = 8;

/// Sector count of the leading data partition.
const DATA_SECTORS: u32 = 8;

/// LBA of the NTFS partition, chosen so it is not the first entry.
const NTFS_START_LBA: u32 = 16;

/// Sector count of the NTFS partition; it runs to the end of the media.
const NTFS_SECTORS: u32 = 48;

/// Write an NTFS boot sector, so the partition is detected as one.
fn write_ntfs_boot_sector(media: &mut [u8], offset: usize) {
    let sector = &mut media[offset..offset + SECTOR_SIZE];
    sector[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

/// Raw media with an MBR whose second partition holds an NTFS volume.
fn mbr_partitioned_media() -> Vec<u8> {
    let mut media = vec![0_u8; MEDIA_SIZE];
    write_ntfs_boot_sector(&mut media, ntfs_offset());
    write_mbr_entry(&mut media[446..462], 0x83, DATA_START_LBA, DATA_SECTORS);
    write_mbr_entry(&mut media[462..478], 0x07, NTFS_START_LBA, NTFS_SECTORS);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

/// Byte offset of the NTFS partition within the media.
fn ntfs_offset() -> usize {
    NTFS_START_LBA as usize * SECTOR_SIZE
}

/// Write the media into a temporary directory and hand back both.
fn image_file() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("disk.bin");
    std::fs::write(&path, mbr_partitioned_media()).expect("write raw image");
    (directory, path)
}

/// Run the built `fsmnt` with these arguments.
fn fsmnt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fsmnt"))
        .args(args)
        .output()
        .expect("run the fsmnt binary")
}

/// The stdout of a successful run, parsed as one JSON document.
fn document(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "the command failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not one JSON document ({error}): {}",
            String::from_utf8_lossy(&output.stdout),
        )
    })
}

/// Every line of stderr, parsed as a JSON object.
///
/// This is the half of the contract a unit test cannot see: a program that
/// reads both streams must never meet a line of prose on either.
fn events(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let event: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("stderr line is not JSON ({error}): {line}"));
            assert!(event.is_object(), "an event is an object: {line}");
            assert_eq!(event["schema"], 1, "every event carries the schema: {line}");
            assert!(
                event["level"].is_string(),
                "every event is keyed by level: {line}"
            );
            event
        })
        .collect()
}

#[test]
fn partitions_prints_one_document_and_nothing_else() {
    let (_directory, path) = image_file();
    let output = fsmnt(&["--json", "partitions", &path.display().to_string()]);
    let document = document(&output);

    assert_eq!(document["schema"], 1);
    assert_eq!(document["kind"], "partitions");
    assert_eq!(document["source"]["kind"], "image");
    assert_eq!(
        document["source"]["path"],
        Value::String(path.display().to_string()),
        "the path comes back exactly as it was typed, so it can be passed on"
    );
    assert_eq!(document["format"], "raw");
    assert_eq!(document["table"], "mbr");
    assert_eq!(document["origin"], "table");
    assert_eq!(document["size_bytes"], MEDIA_SIZE);
    assert_eq!(document["sector_size"], 512);

    let partitions = document["partitions"].as_array().expect("an array");
    assert_eq!(partitions.len(), 2);
    assert_eq!(partitions[0]["ordinal"], 0);
    assert_eq!(partitions[0]["offset"], DATA_START_LBA * 512);
    assert_eq!(partitions[1]["ordinal"], 1);
    assert_eq!(partitions[1]["offset"], ntfs_offset());
    assert_eq!(partitions[1]["filesystem"], "ntfs");
    assert_eq!(partitions[1]["size_bytes"], NTFS_SECTORS * 512);

    events(&output);
}

#[test]
fn scan_prints_one_document_of_hits() {
    let (_directory, path) = image_file();
    let output = fsmnt(&["scan", "--json", &path.display().to_string()]);
    let document = document(&output);

    assert_eq!(document["schema"], 1);
    assert_eq!(document["kind"], "scan");
    assert_eq!(document["stride"], 4096);
    assert_eq!(document["sector_size"], 512);
    assert_eq!(document["format"], "raw");

    let hits = document["hits"].as_array().expect("an array");
    let table = hits
        .iter()
        .find(|hit| hit["kind"] == "partition_table")
        .expect("the MBR is found where it is");
    assert_eq!(table["offset"], 0);
    assert_eq!(table["filesystem"], "mbr");
    assert_eq!(
        table["ordinal"],
        Value::Null,
        "a partition table is not mountable, so it is not numbered"
    );
    assert_eq!(table["mount_command"], Value::Null);

    let filesystem = hits
        .iter()
        .find(|hit| hit["kind"] == "filesystem")
        .expect("the NTFS volume is found where the table says it is");
    assert_eq!(filesystem["offset"], ntfs_offset());
    assert_eq!(filesystem["sector"], NTFS_START_LBA);
    assert_eq!(filesystem["filesystem"], "ntfs");
    assert_eq!(filesystem["ordinal"], 0);
    assert_eq!(
        filesystem["mount_command"],
        serde_json::json!(["--offset", ntfs_offset().to_string()]),
        "the way in is a list of arguments, not a shell string to re-split"
    );

    assert!(
        output.stderr.is_empty(),
        "an unflagged successful scan emits no routine log events: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_failure_leaves_stdout_empty_and_says_why_on_stderr() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let output = fsmnt(&[
        "--json",
        "partitions",
        &directory.path().display().to_string(),
    ]);

    assert!(!output.status.success(), "a directory has no partitions");
    assert_eq!(output.status.code(), Some(1), "the exit code is unchanged");
    assert!(
        output.stdout.is_empty(),
        "stdout is either empty or valid JSON, never half a document: {}",
        String::from_utf8_lossy(&output.stdout),
    );

    let events = events(&output);
    let error = events
        .iter()
        .find(|event| event["level"] == "ERROR")
        .expect("the failure is one ERROR event");
    assert!(
        error["message"]
            .as_str()
            .expect("a message")
            .contains("is a directory"),
        "{error}"
    );
}

#[test]
fn a_parse_failure_is_still_one_json_stderr_event() {
    let output = fsmnt(&["--json", "partitions"]);

    assert!(!output.status.success(), "a required source is missing");
    assert_eq!(output.status.code(), Some(2), "clap keeps its exit code");
    assert!(output.stdout.is_empty(), "a parse failure has no product");

    let events = events(&output);
    assert_eq!(events.len(), 1, "one parse failure is one event");
    assert_eq!(events[0]["level"], "ERROR");
    assert!(
        events[0]["message"]
            .as_str()
            .expect("a message")
            .contains("required arguments were not provided"),
        "{}",
        events[0]
    );
}

#[test]
fn a_logging_setup_failure_is_still_one_json_stderr_event() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let output = fsmnt(&[
        "--json",
        "--log-file",
        &directory.path().display().to_string(),
        "drives",
    ]);

    assert!(!output.status.success(), "a directory cannot be a log file");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "startup has no command product");

    let events = events(&output);
    assert_eq!(events.len(), 1, "one setup failure is one event");
    assert_eq!(events[0]["level"], "ERROR");
    assert!(
        events[0]["message"]
            .as_str()
            .expect("a message")
            .contains("failed to open log file"),
        "{}",
        events[0]
    );
}

/// The stdout of a successful run, as a person reads it.
fn table(output: &Output) -> String {
    assert!(
        output.status.success(),
        "the command failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        serde_json::from_str::<Value>(&stdout).is_err(),
        "without --json nothing on stdout is JSON: {stdout}"
    );
    stdout
}

#[test]
fn the_partition_table_is_untouched_without_the_flag() {
    let (_directory, path) = image_file();
    let stdout = table(&fsmnt(&["partitions", &path.display().to_string()]));

    assert!(stdout.contains("MBR partition table"), "{stdout}");
    for column in ["#", "TYPE", "SIZE", "OFFSET", "FILESYSTEM"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.contains("OFFSET") && line.contains(column)),
            "the header still carries {column}: {stdout}"
        );
    }
    assert!(
        stdout.contains(&format!("  {}  ", ntfs_offset())),
        "and the NTFS partition's offset is in the OFFSET column: {stdout}"
    );
    assert!(
        stdout.contains("Mount one with: fsmnt mount "),
        "including the hint that only a person needs: {stdout}"
    );
}

#[test]
fn the_scan_table_is_untouched_without_the_flag() {
    let (_directory, path) = image_file();
    let stdout = table(&fsmnt(&["scan", &path.display().to_string()]));

    assert!(
        stdout.starts_with(&format!("{}: raw image, ", path.display())),
        "the scan says what it searched before it says what it found: {stdout}"
    );
    for column in ["#", "OFFSET", "SECTOR", "TYPE", "SIZE", "NOTE"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.contains("SECTOR") && line.contains(column)),
            "the header still carries {column}: {stdout}"
        );
    }
    assert!(
        stdout.contains("partition table; list it with `fsmnt partitions`"),
        "the NOTE column is the same sentence the JSON `note` carries: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "Mount one with: fsmnt mount {} <MOUNTPOINT> --offset {}",
            path.display(),
            ntfs_offset()
        )),
        "and the hint offers the offset the document's mount_command carries: {stdout}"
    );
}
