//! What the single `SOURCE` positional can be, and how it is decided.
//!
//! `drives`, `partitions`, `scan` and `mount` all take one source, spelled
//! the same way everywhere: a directory, a disk image, or a drive. Deciding
//! which is a small piece of guesswork, so it lives in one place, is
//! explained in `--help`, and can always be overridden with `--dir`,
//! `--image` or `--drive` when the guess is wrong (a raw dump named
//! `sda`, an image that does not exist yet, a drive whose ID looks like a
//! filename).

use std::fmt;
use std::path::{Path, PathBuf};

use fsmnt::device::HostDriveId;

/// The three things a `SOURCE` can name, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// A host directory, exposed as a volume of its own.
    Directory(PathBuf),
    /// A raw, EWF, VHD or VHDX disk image.
    Image(PathBuf),
    /// A physical drive attached to this machine.
    Drive(HostDriveId),
}

impl Source {
    /// Which kind this is, for the applicability rules.
    pub(crate) const fn kind(&self) -> SourceKind {
        match self {
            Self::Directory(_) => SourceKind::Directory,
            Self::Image(_) => SourceKind::Image,
            Self::Drive(_) => SourceKind::Drive,
        }
    }

    /// What to call this source in a message: "directory", "disk image",
    /// or "drive".
    pub(crate) const fn describe(&self) -> &'static str {
        self.kind().describe()
    }
}

impl fmt::Display for Source {
    /// The source as the user identified it, so a message or a suggested
    /// command line can be pasted back into a shell.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) | Self::Image(path) => write!(formatter, "{}", path.display()),
            Self::Drive(id) => write!(formatter, "{id}"),
        }
    }
}

/// What a source is, either as a caller's override or as the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceKind {
    /// Decide from the text and the filesystem; see [`resolve`].
    Auto,
    /// A host directory, stated with `--dir`.
    Directory,
    /// A disk image, stated with `--image`.
    Image,
    /// A physical drive, stated with `--drive`.
    Drive,
}

impl SourceKind {
    /// The caller's override, or [`Auto`](Self::Auto) when they made none.
    pub(crate) const fn from_flags(dir: bool, image: bool, drive: bool) -> Self {
        // Mutually exclusive in clap, so at most one is set.
        if dir {
            Self::Directory
        } else if image {
            Self::Image
        } else if drive {
            Self::Drive
        } else {
            Self::Auto
        }
    }

    /// Singular noun for this kind.
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::Auto | Self::Directory => "directory",
            Self::Image => "disk image",
            Self::Drive => "drive",
        }
    }

    /// Plural noun, for "`--raw` applies to drives".
    const fn plural(self) -> &'static str {
        match self {
            Self::Auto | Self::Directory => "directories",
            Self::Image => "disk images",
            Self::Drive => "drives",
        }
    }
}

/// Decide what `text` names.
///
/// With no override the order is: an existing directory is a directory; an
/// existing regular file is an image; an operating-system device path is a
/// drive; anything with a path separator or a file extension is an image
/// (so a mistyped path fails as "cannot open image" rather than as "no such
/// drive"); and a bare token left over is a drive ID.
///
/// The overrides do exactly what they say. `--image` never touches the
/// filesystem, because the point of stating it is to get the image error
/// rather than a guess. `--drive` accepts a device path and normalises it
/// to the ID `fsmnt drives` prints. `--dir` is the only one that can fail,
/// since a directory that is not there cannot be exposed.
///
/// # Errors
///
/// Returns an error if `--dir` names something that is not a directory.
pub(crate) fn resolve(text: &str, kind: SourceKind) -> Result<Source, Box<dyn std::error::Error>> {
    match kind {
        SourceKind::Directory => {
            let path = PathBuf::from(text);
            if !path.is_dir() {
                return Err(format!(
                    "--dir expects a directory; {text} is not one — drop --dir to open it as a \
                     disk image, or --drive to read it as a drive"
                )
                .into());
            }
            Ok(Source::Directory(path))
        }
        SourceKind::Image => Ok(Source::Image(PathBuf::from(text))),
        SourceKind::Drive => Ok(Source::Drive(HostDriveId::new(
            normalize_drive_id(text).unwrap_or_else(|| text.to_string()),
        ))),
        SourceKind::Auto => Ok(auto_resolve(text)),
    }
}

/// [`resolve`]'s guess, when the caller stated no kind.
fn auto_resolve(text: &str) -> Source {
    let path = Path::new(text);
    if path.is_dir() {
        return Source::Directory(path.to_path_buf());
    }
    if path.is_file() {
        return Source::Image(path.to_path_buf());
    }
    // A device path is checked before the separator rule, or every
    // `\\.\PhysicalDrive0` and `/dev/sda` would be read as a file path.
    if let Some(id) = normalize_drive_id(text) {
        return Source::Drive(HostDriveId::new(id));
    }
    if text.contains(['/', '\\']) || path.extension().is_some() {
        return Source::Image(path.to_path_buf());
    }
    Source::Drive(HostDriveId::new(text))
}

/// The drive ID an operating-system device path names, or `None` when the
/// text is not one.
///
/// Windows spells a drive `\\.\PhysicalDrive0` or `\\?\PhysicalDrive0`,
/// Linux `/dev/sda`, macOS `/dev/disk2` — and `/dev/rdisk2` for the same
/// media opened unbuffered, which is the same drive. All of them reduce to
/// what `fsmnt drives` prints.
fn normalize_drive_id(text: &str) -> Option<String> {
    const PHYSICAL_DRIVE: &str = "PhysicalDrive";

    let device = text
        .strip_prefix(r"\\.\")
        .or_else(|| text.strip_prefix(r"\\?\"))
        .unwrap_or(text);
    if let Some(prefix) = device.get(..PHYSICAL_DRIVE.len())
        && prefix.eq_ignore_ascii_case(PHYSICAL_DRIVE)
    {
        let number = &device[PHYSICAL_DRIVE.len()..];
        if !number.is_empty() {
            return Some(number.to_string());
        }
    }

    let node = text.strip_prefix("/dev/")?;
    if node.is_empty() || node.contains('/') {
        return None;
    }
    // `/dev/rdisk2` is `/dev/disk2` without the buffer cache; both name
    // drive `disk2`.
    if let Some(disk) = node.strip_prefix('r')
        && disk.starts_with("disk")
    {
        return Some(disk.to_string());
    }
    Some(node.to_string())
}

/// Refuse an option the resolved source cannot use.
///
/// `flags` lists what the command line set, each with the source kinds it
/// means anything for. The message names both halves — the option and what
/// the source turned out to be — because the usual cause is a source that
/// resolved to something other than what the caller had in mind.
///
/// # Errors
///
/// Returns an error for the first flag that is set and does not apply.
pub(crate) fn check_applicability(
    source: &Source,
    flags: &[(&str, bool, &[SourceKind])],
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = source.kind();
    for (flag, is_set, applies_to) in flags {
        if *is_set && !applies_to.contains(&kind) {
            return Err(format!(
                "{flag} applies to {}; {source} is a {}",
                applies_phrase(applies_to),
                source.describe(),
            )
            .into());
        }
    }
    Ok(())
}

/// "drives", or "disk images and drives": the kinds an option is for.
fn applies_phrase(kinds: &[SourceKind]) -> String {
    let names: Vec<&str> = kinds.iter().map(|kind| kind.plural()).collect();
    match names.split_last() {
        None => "nothing".to_string(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Source, SourceKind, check_applicability, normalize_drive_id, resolve};
    use std::path::PathBuf;

    fn auto(text: &str) -> Source {
        resolve(text, SourceKind::Auto).expect("automatic resolution never fails")
    }

    #[test]
    fn an_existing_directory_is_a_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let text = dir.path().to_string_lossy().into_owned();
        assert_eq!(auto(&text), Source::Directory(dir.path().to_path_buf()));
        assert_eq!(
            resolve(&text, SourceKind::Image).expect("forced image"),
            Source::Image(dir.path().to_path_buf()),
            "--image is a statement, not a guess"
        );
    }

    #[test]
    fn an_existing_file_is_an_image_even_without_an_extension() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("rawdump");
        std::fs::write(&file, b"not a disk").expect("write fixture");
        assert_eq!(auto(&file.to_string_lossy()), Source::Image(file));
        assert!(
            matches!(auto("rawdump"), Source::Drive(_)),
            "no such file in the working directory, and no extension to go on"
        );
    }

    #[test]
    fn a_path_separator_or_an_extension_means_an_image() {
        for text in [
            "disk.bin",
            "evidence.E01",
            "sub/dir/raw",
            r"C:\images\win11.vhdx",
            "./image",
        ] {
            assert_eq!(
                auto(text),
                Source::Image(PathBuf::from(text)),
                "{text} should be read as an image path"
            );
        }
    }

    #[test]
    fn a_bare_token_is_a_drive_id() {
        for text in ["0", "1", "sda", "sdb1", "disk2", "nvme0n1"] {
            assert_eq!(
                auto(text),
                Source::Drive(fsmnt::device::HostDriveId::new(text)),
                "{text} should be read as a drive ID"
            );
        }
    }

    #[test]
    fn device_paths_are_normalized_to_the_id_drives_prints() {
        for (text, id) in [
            (r"\\.\PhysicalDrive0", "0"),
            (r"\\?\PhysicalDrive12", "12"),
            (r"\\.\physicaldrive3", "3"),
            ("PhysicalDrive0", "0"),
            ("/dev/sda", "sda"),
            ("/dev/nvme0n1", "nvme0n1"),
            ("/dev/disk2", "disk2"),
            ("/dev/rdisk2", "disk2"),
        ] {
            assert_eq!(normalize_drive_id(text).as_deref(), Some(id), "{text}");
            assert_eq!(
                auto(text),
                Source::Drive(fsmnt::device::HostDriveId::new(id)),
                "{text} should resolve to drive {id}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_device_path_is_left_alone() {
        for text in ["0", "sda", "disk.bin", "/dev/", "/dev/disk/by-uuid/x", ""] {
            assert_eq!(normalize_drive_id(text), None, "{text}");
        }
        assert_eq!(
            normalize_drive_id("/dev/rtx"),
            Some("rtx".to_string()),
            "only a leading r on a disk node is the unbuffered spelling"
        );
    }

    #[test]
    fn the_drive_override_also_normalizes_a_device_path() {
        assert_eq!(
            resolve(r"\\.\PhysicalDrive2", SourceKind::Drive).expect("forced drive"),
            Source::Drive(fsmnt::device::HostDriveId::new("2"))
        );
        assert_eq!(
            resolve("disk.bin", SourceKind::Drive).expect("forced drive"),
            Source::Drive(fsmnt::device::HostDriveId::new("disk.bin")),
            "an unrecognised spelling is passed to the enumerator as written"
        );
    }

    #[test]
    fn the_directory_override_names_the_path_it_could_not_use() {
        let error = resolve("no-such-directory-here", SourceKind::Directory)
            .expect_err("--dir on a missing path");
        let message = error.to_string();
        assert!(message.contains("no-such-directory-here"), "{message}");
        assert!(message.contains("--dir"), "{message}");
    }

    #[test]
    fn an_option_names_both_itself_and_what_the_source_turned_out_to_be() {
        let image = Source::Image(PathBuf::from("disk.bin"));
        let error = check_applicability(&image, &[("--raw", true, &[SourceKind::Drive])])
            .expect_err("--raw on an image");
        assert_eq!(
            error.to_string(),
            "--raw applies to drives; disk.bin is a disk image"
        );

        let directory = Source::Directory(PathBuf::from("export"));
        let error = check_applicability(
            &directory,
            &[("--partition", true, &[SourceKind::Image, SourceKind::Drive])],
        )
        .expect_err("--partition on a directory");
        assert_eq!(
            error.to_string(),
            "--partition applies to disk images and drives; export is a directory"
        );
    }

    #[test]
    fn an_option_that_applies_or_was_never_set_passes() {
        let drive = Source::Drive(fsmnt::device::HostDriveId::new("0"));
        check_applicability(
            &drive,
            &[
                ("--raw", true, &[SourceKind::Drive]),
                ("--fs-root", false, &[SourceKind::Image]),
            ],
        )
        .expect("both are fine");
    }
}
