//! Parser for Linux-style filesystem tables.

use std::str::FromStr;

/// A parsed filesystem table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fstab {
    entries: Vec<FstabEntry>,
}

impl Fstab {
    /// Entries in source order.
    #[must_use]
    pub fn entries(&self) -> &[FstabEntry] {
        &self.entries
    }
}

impl FromStr for Fstab {
    type Err = FstabParseError;

    fn from_str(contents: &str) -> Result<Self, Self::Err> {
        let mut entries = Vec::new();
        for (index, raw_line) in contents.lines().enumerate() {
            let line_number = index.saturating_add(1);
            let line = raw_line.split_once('#').map_or(raw_line, |(line, _)| line);
            if line.trim().is_empty() {
                continue;
            }
            entries.push(parse_entry(line, line_number)?);
        }
        Ok(Self { entries })
    }
}

/// One mount declaration from an [`Fstab`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FstabEntry {
    source: FstabSource,
    mount_point: String,
    filesystem_type: String,
    options: Vec<String>,
    dump_frequency: u32,
    pass_number: u32,
}

impl FstabEntry {
    /// Device or filesystem identity supplying this mount.
    #[must_use]
    pub const fn source(&self) -> &FstabSource {
        &self.source
    }

    /// Absolute namespace path where this filesystem is attached.
    #[must_use]
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// Filesystem type requested by the table, such as `btrfs` or `ext4`.
    #[must_use]
    pub fn filesystem_type(&self) -> &str {
        &self.filesystem_type
    }

    /// Comma-separated mount options, decoded into individual values.
    #[must_use]
    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Return whether an exact flag-style mount option is present.
    #[must_use]
    pub fn has_option(&self, requested: &str) -> bool {
        self.options.iter().any(|option| option == requested)
    }

    /// Return the value of the first `name=value` mount option.
    #[must_use]
    pub fn option(&self, requested: &str) -> Option<&str> {
        self.options.iter().find_map(|option| {
            let (name, value) = option.split_once('=')?;
            (name == requested).then_some(value)
        })
    }

    /// `dump(8)` backup frequency field.
    #[must_use]
    pub const fn dump_frequency(&self) -> u32 {
        self.dump_frequency
    }

    /// Filesystem-check order field.
    #[must_use]
    pub const fn pass_number(&self) -> u32 {
        self.pass_number
    }
}

/// Source syntax accepted in an fstab entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FstabSource {
    /// Match a filesystem's canonical UUID.
    Uuid(String),
    /// Match a filesystem label.
    Label(String),
    /// Match a partition-table UUID.
    PartitionUuid(String),
    /// Match a partition-table label.
    PartitionLabel(String),
    /// Open a device path named by the guest operating system.
    Device(String),
    /// No block-device source, as used by virtual filesystems.
    None,
}

impl FstabSource {
    fn parse(value: String) -> Self {
        if value == "none" {
            Self::None
        } else if let Some(uuid) = value.strip_prefix("UUID=") {
            Self::Uuid(uuid.to_string())
        } else if let Some(label) = value.strip_prefix("LABEL=") {
            Self::Label(label.to_string())
        } else if let Some(uuid) = value.strip_prefix("PARTUUID=") {
            Self::PartitionUuid(uuid.to_string())
        } else if let Some(label) = value.strip_prefix("PARTLABEL=") {
            Self::PartitionLabel(label.to_string())
        } else {
            Self::Device(value)
        }
    }
}

/// A malformed non-comment fstab line.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid fstab line {line}: {message}")]
pub struct FstabParseError {
    line: usize,
    message: String,
}

impl FstabParseError {
    /// One-based source line containing the error.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }
}

fn parse_entry(line: &str, line_number: usize) -> Result<FstabEntry, FstabParseError> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if !(4..=6).contains(&fields.len()) {
        return Err(parse_error(
            line_number,
            "expected four to six whitespace-separated fields",
        ));
    }
    let source = FstabSource::parse(decode_field(fields[0], line_number)?);
    let mount_point = decode_field(fields[1], line_number)?;
    let filesystem_type = decode_field(fields[2], line_number)?;
    let options = decode_field(fields[3], line_number)?
        .split(',')
        .filter(|option| !option.is_empty())
        .map(str::to_string)
        .collect();
    let dump_frequency = parse_number(fields.get(4).copied().unwrap_or("0"), line_number)?;
    let pass_number = parse_number(fields.get(5).copied().unwrap_or("0"), line_number)?;
    Ok(FstabEntry {
        source,
        mount_point,
        filesystem_type,
        options,
        dump_frequency,
        pass_number,
    })
}

fn decode_field(field: &str, line_number: usize) -> Result<String, FstabParseError> {
    let bytes = field.as_bytes();
    let mut output = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index]);
            index = index.saturating_add(1);
            continue;
        }
        let Some(octal) = bytes.get(index.saturating_add(1)..index.saturating_add(4)) else {
            return Err(parse_error(line_number, "truncated field escape"));
        };
        if !octal.iter().all(u8::is_ascii_digit) || octal.iter().any(|digit| *digit > b'7') {
            return Err(parse_error(line_number, "field escape is not octal"));
        }
        let value = octal.iter().fold(0_u8, |value, digit| {
            value
                .saturating_mul(8)
                .saturating_add(digit.saturating_sub(b'0'))
        });
        output.push(value);
        index = index.saturating_add(4);
    }
    String::from_utf8(output).map_err(|_| parse_error(line_number, "field is not valid UTF-8"))
}

fn parse_number(value: &str, line_number: usize) -> Result<u32, FstabParseError> {
    value
        .parse()
        .map_err(|_| parse_error(line_number, "dump/pass field is not an unsigned integer"))
}

fn parse_error(line: usize, message: &str) -> FstabParseError {
    FstabParseError {
        line,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r"
# Fedora installation
UUID=df09cc9f-a463-49ea-9ff7-b7ee9cb145f4 / btrfs subvol=root,compress=zstd:1 0 0
UUID=24defc6f-0bcf-45c0-bda5-f93e3f9c92a5 /boot ext4 defaults 1 2
UUID=DC98-BD27 /boot/efi vfat umask=0077,shortname=winnt 0 2
UUID=df09cc9f-a463-49ea-9ff7-b7ee9cb145f4 /home btrfs subvol=home,compress=zstd:1 0 0
";

    #[test]
    fn parses_realistic_uuid_mounts_and_options() {
        let fstab: Fstab = EXAMPLE.parse().expect("valid fstab");
        assert_eq!(fstab.entries().len(), 4);
        let root = &fstab.entries()[0];
        assert_eq!(
            root.source(),
            &FstabSource::Uuid("df09cc9f-a463-49ea-9ff7-b7ee9cb145f4".to_string())
        );
        assert_eq!(root.mount_point(), "/");
        assert_eq!(root.filesystem_type(), "btrfs");
        assert_eq!(root.option("subvol"), Some("root"));
        assert_eq!(root.option("compress"), Some("zstd:1"));
        assert_eq!(root.dump_frequency(), 0);
        assert_eq!(root.pass_number(), 0);
    }

    #[test]
    fn decodes_standard_fstab_field_escapes() {
        let fstab: Fstab = r"LABEL=My\040Disk /media/My\040Disk ext4 x-name=a\134b 0 0"
            .parse()
            .expect("escaped fstab");
        let entry = &fstab.entries()[0];
        assert_eq!(entry.source(), &FstabSource::Label("My Disk".to_string()));
        assert_eq!(entry.mount_point(), "/media/My Disk");
        assert_eq!(entry.option("x-name"), Some(r"a\b"));
    }

    #[test]
    fn rejects_bad_field_counts_escapes_and_numbers() {
        for (contents, line) in [
            ("UUID=x /", 1),
            (r"UUID=x /bad\09x ext4 defaults 0 0", 1),
            ("UUID=x / ext4 defaults never 0", 1),
            ("\n# comment\nUUID=x / ext4", 3),
        ] {
            let error = contents.parse::<Fstab>().expect_err("malformed fstab");
            assert_eq!(error.line(), line);
        }
    }
}
