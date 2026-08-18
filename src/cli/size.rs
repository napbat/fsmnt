//! Human-friendly size expressions for byte offsets and sector sizes.
//!
//! Forensic offsets are quoted in whatever unit the tool that produced them
//! used: `fdisk` prints sectors, a partition table prints bytes, and a
//! write-up says "258 MiB". [`SizeExpr`] accepts all three so an offset can
//! be pasted rather than recomputed.
//!
//! A sector count (`528384s`) cannot be resolved until `--sector-size` is
//! known, which clap parses as a separate argument, so parsing and
//! resolution are two steps: [`SizeExpr::from_str`] validates the spelling
//! and [`SizeExpr::resolve`] turns it into bytes.

use std::fmt;
use std::str::FromStr;

/// Sector size assumed when a command does not carry `--sector-size`.
pub(crate) const DEFAULT_SECTOR_SIZE: u32 = 512;

/// The largest sector size `--sector-size` accepts.
///
/// Real media tops out at 4096; the ceiling only exists to keep a typo from
/// asking for a multi-gigabyte sector buffer.
const MAX_SECTOR_SIZE: u32 = 1 << 20;

/// A size written as bytes, as a binary/decimal multiple, or as a count of
/// sectors.
///
/// Sector counts stay unresolved until the sector size is known; every
/// other spelling is already a byte count when it is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SizeExpr {
    /// An absolute byte count, from a plain number or a unit suffix.
    Bytes(u64),
    /// A count of sectors, resolved against the selected sector size.
    Sectors(u64),
}

impl SizeExpr {
    /// The byte count this expression denotes at `sector_size`.
    ///
    /// # Errors
    ///
    /// Returns an error if a sector count times the sector size overflows
    /// `u64`.
    pub(crate) fn resolve(self, sector_size: u32) -> Result<u64, SizeParseError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Sectors(sectors) => sectors
                .checked_mul(u64::from(sector_size))
                .ok_or(SizeParseError::Overflow),
        }
    }
}

impl fmt::Display for SizeExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => write!(f, "{bytes}"),
            Self::Sectors(sectors) => write!(f, "{sectors}s"),
        }
    }
}

/// Why a size expression could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SizeParseError {
    /// Nothing, or only whitespace, was supplied.
    #[error("expected a size such as 1048576, 1MiB, 1MB, or 2048s")]
    Empty,
    /// The leading digits are missing or malformed.
    #[error("'{0}' does not start with a number")]
    NotANumber(String),
    /// The trailing unit is not one this parser knows.
    #[error(
        "unknown size unit '{0}'; use bytes (B), binary K/M/G/T or KiB/MiB/GiB/TiB, decimal KB/MB/GB/TB, or s for sectors"
    )]
    UnknownUnit(String),
    /// The value does not fit in a `u64` byte count.
    #[error("size does not fit in 64 bits")]
    Overflow,
}

impl FromStr for SizeExpr {
    type Err = SizeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(SizeParseError::Empty);
        }
        let digits_end = trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len());
        let (digits, unit) = trimmed.split_at(digits_end);
        if digits.is_empty() {
            return Err(SizeParseError::NotANumber(trimmed.to_string()));
        }
        let value: u64 = digits
            .parse()
            .map_err(|_| SizeParseError::NotANumber(trimmed.to_string()))?;

        let unit = unit.trim();
        if unit.eq_ignore_ascii_case("s") {
            return Ok(Self::Sectors(value));
        }
        let multiplier =
            unit_multiplier(unit).ok_or_else(|| SizeParseError::UnknownUnit(unit.to_string()))?;
        value
            .checked_mul(multiplier)
            .map(Self::Bytes)
            .ok_or(SizeParseError::Overflow)
    }
}

/// Byte multiplier for a unit suffix, or `None` if it is not a known unit.
///
/// A bare letter is binary (`1M` is 1 MiB, as `fdisk` and `parted` print
/// it); the explicit `KB`/`MB`/`GB`/`TB` spellings are decimal, matching how
/// drive capacities are advertised.
fn unit_multiplier(unit: &str) -> Option<u64> {
    const KIB: u64 = 1024;
    const KB: u64 = 1000;
    let unit = unit.to_ascii_lowercase();
    Some(match unit.as_str() {
        "" | "b" => 1,
        "k" | "kib" => KIB,
        "m" | "mib" => KIB * KIB,
        "g" | "gib" => KIB * KIB * KIB,
        "t" | "tib" => KIB * KIB * KIB * KIB,
        "kb" => KB,
        "mb" => KB * KB,
        "gb" => KB * KB * KB,
        "tb" => KB * KB * KB * KB,
        _ => return None,
    })
}

/// clap value parser for `--offset`.
///
/// # Errors
///
/// Returns the parse failure's message when the expression is malformed.
pub(crate) fn parse_size_expr(value: &str) -> Result<SizeExpr, String> {
    value
        .parse()
        .map_err(|error: SizeParseError| error.to_string())
}

/// clap value parser for `--sector-size`.
///
/// # Errors
///
/// Returns an error when the value is not a power of two, is below 512, or
/// exceeds the accepted ceiling.
pub(crate) fn parse_sector_size(value: &str) -> Result<u32, String> {
    let expr: SizeExpr = value.parse().map_err(|e: SizeParseError| e.to_string())?;
    let SizeExpr::Bytes(bytes) = expr else {
        return Err("sector size is a byte count; the 's' suffix means sectors".to_string());
    };
    let size = u32::try_from(bytes).map_err(|_| {
        format!("sector size {bytes} is larger than the maximum of {MAX_SECTOR_SIZE}")
    })?;
    if size < DEFAULT_SECTOR_SIZE {
        return Err(format!(
            "sector size {size} is smaller than the minimum of {DEFAULT_SECTOR_SIZE}"
        ));
    }
    if size > MAX_SECTOR_SIZE {
        return Err(format!(
            "sector size {size} is larger than the maximum of {MAX_SECTOR_SIZE}"
        ));
    }
    if !size.is_power_of_two() {
        return Err(format!("sector size {size} is not a power of two"));
    }
    Ok(size)
}

/// Format a byte count the way the truncation warning quotes it: two
/// decimals from a gigabyte up, and a unit small enough that the shortfall
/// never rounds away to "0" below that.
///
/// The table formatter in [`super::format_size`](super::format_size) rounds
/// harder because it has a column to fit; a warning that names two sizes
/// side by side has to make the difference between them visible.
pub(crate) fn format_size_precise(bytes: u64) -> String {
    const KB: u64 = 1000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;
    if bytes < KB {
        return format!("{bytes} bytes");
    }
    if bytes < MB {
        return format!("{} KB", bytes / KB);
    }
    if bytes < GB {
        return format!("{} MB", bytes / MB);
    }
    let whole = bytes / GB;
    let hundredths = (bytes % GB) / 10_000_000;
    format!("{whole}.{hundredths:02} GB")
}

#[cfg(test)]
mod tests {
    use super::{SizeExpr, SizeParseError, format_size_precise, parse_sector_size};

    #[test]
    fn plain_numbers_are_bytes() {
        assert_eq!("270532608".parse(), Ok(SizeExpr::Bytes(270_532_608)));
        assert_eq!("0".parse(), Ok(SizeExpr::Bytes(0)));
        assert_eq!("4096B".parse(), Ok(SizeExpr::Bytes(4096)));
    }

    #[test]
    fn binary_suffixes_are_powers_of_two() {
        assert_eq!("1M".parse(), Ok(SizeExpr::Bytes(1_048_576)));
        assert_eq!("258MiB".parse(), Ok(SizeExpr::Bytes(270_532_608)));
        assert_eq!("1K".parse(), Ok(SizeExpr::Bytes(1024)));
        assert_eq!("2GiB".parse(), Ok(SizeExpr::Bytes(2_147_483_648)));
        assert_eq!("1TiB".parse(), Ok(SizeExpr::Bytes(1_099_511_627_776)));
    }

    #[test]
    fn decimal_suffixes_are_powers_of_ten() {
        assert_eq!("1KB".parse(), Ok(SizeExpr::Bytes(1000)));
        assert_eq!("1MB".parse(), Ok(SizeExpr::Bytes(1_000_000)));
        assert_eq!("5GB".parse(), Ok(SizeExpr::Bytes(5_000_000_000)));
    }

    #[test]
    fn suffixes_are_case_insensitive_but_still_distinguish_binary_from_decimal() {
        assert_eq!("1mib".parse(), Ok(SizeExpr::Bytes(1_048_576)));
        assert_eq!("1mb".parse(), Ok(SizeExpr::Bytes(1_000_000)));
        assert_eq!("1m".parse::<SizeExpr>(), "1MiB".parse());
    }

    #[test]
    fn the_s_suffix_stays_a_sector_count_until_a_sector_size_is_known() {
        let expr: SizeExpr = "528384s".parse().expect("sector expression");
        assert_eq!(expr, SizeExpr::Sectors(528_384));
        assert_eq!(expr.resolve(512), Ok(270_532_608));
        assert_eq!(expr.resolve(4096), Ok(2_164_260_864));

        let expr: SizeExpr = "4096s".parse().expect("sector expression");
        assert_eq!(expr.resolve(65536), Ok(268_435_456));
    }

    #[test]
    fn byte_expressions_ignore_the_sector_size() {
        let expr: SizeExpr = "258MiB".parse().expect("size expression");
        assert_eq!(expr.resolve(4096), Ok(270_532_608));
    }

    #[test]
    fn whitespace_between_number_and_unit_is_accepted() {
        assert_eq!(" 258 MiB ".parse(), Ok(SizeExpr::Bytes(270_532_608)));
    }

    #[test]
    fn malformed_expressions_are_rejected() {
        assert_eq!("".parse::<SizeExpr>(), Err(SizeParseError::Empty));
        assert_eq!("   ".parse::<SizeExpr>(), Err(SizeParseError::Empty));
        assert!(matches!(
            "MiB".parse::<SizeExpr>(),
            Err(SizeParseError::NotANumber(_))
        ));
        assert!(matches!(
            "-1".parse::<SizeExpr>(),
            Err(SizeParseError::NotANumber(_))
        ));
        assert!(matches!(
            "12ZB".parse::<SizeExpr>(),
            Err(SizeParseError::UnknownUnit(_))
        ));
        assert!(matches!(
            "1.5M".parse::<SizeExpr>(),
            Err(SizeParseError::UnknownUnit(_)),
        ));
    }

    #[test]
    fn overflow_is_an_error_rather_than_a_wrap() {
        assert_eq!(
            "18446744073709551615TiB".parse::<SizeExpr>(),
            Err(SizeParseError::Overflow)
        );
        assert_eq!(
            SizeExpr::Sectors(u64::MAX).resolve(4096),
            Err(SizeParseError::Overflow)
        );
    }

    #[test]
    fn sector_sizes_must_be_powers_of_two_of_at_least_512() {
        assert_eq!(parse_sector_size("512"), Ok(512));
        assert_eq!(parse_sector_size("4096"), Ok(4096));
        assert_eq!(parse_sector_size("4K"), Ok(4096));
        assert_eq!(parse_sector_size("65536"), Ok(65_536));

        for bad in ["0", "256", "4095", "1536", "2097152", "512s"] {
            assert!(
                parse_sector_size(bad).is_err(),
                "{bad} should not be a sector size"
            );
        }
    }

    #[test]
    fn the_warning_formatter_keeps_the_difference_visible() {
        assert_eq!(format_size_precise(1_560_440_832), "1.56 GB");
        assert_eq!(format_size_precise(1_438_777_344), "1.43 GB");
        assert_eq!(format_size_precise(121_663_488), "121 MB");
    }

    #[test]
    fn a_small_shortfall_still_has_a_number() {
        assert_eq!(format_size_precise(3_035_136), "3 MB");
        assert_eq!(format_size_precise(65_536), "65 KB");
        assert_eq!(format_size_precise(512), "512 bytes");
        assert_eq!(format_size_precise(0), "0 bytes");
    }
}
