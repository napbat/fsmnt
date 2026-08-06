use core::ops::RangeInclusive;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U64, Unaligned};

/// Difference in 100-nanosecond intervals between the Windows/NTFS epoch (1601-01-01) and the Unix epoch (1970-01-01).
#[cfg(any(feature = "chrono", feature = "time", feature = "std"))]
const EPOCH_DIFFERENCE_IN_INTERVALS: i64 = 116_444_736_000_000_000;

/// Number of 100-nanosecond intervals in a second.
#[cfg(any(feature = "chrono", feature = "std"))]
const INTERVALS_PER_SECOND: u64 = 10_000_000;

/// Difference in seconds between the Windows/NTFS epoch (1601-01-01) and the Unix epoch (1970-01-01).
#[cfg(feature = "chrono")]
const EPOCH_DIFFERENCE_IN_SECONDS: i64 =
    EPOCH_DIFFERENCE_IN_INTERVALS / (INTERVALS_PER_SECOND as i64);

/// An NTFS timestamp, used for expressing file times.
///
/// NTFS (and the Windows NT line of operating systems) represent time as an unsigned 64-bit integer
/// counting the number of 100-nanosecond intervals since January 1, 1601.
#[derive(
    Clone, Copy, Debug, Eq, FromBytes, Immutable, KnownLayout, Ord, PartialEq, PartialOrd, Unaligned,
)]
#[repr(transparent)]
pub struct NtfsTime(U64<LittleEndian>);

impl NtfsTime {
    /// Returns the stored NT timestamp (number of 100-nanosecond intervals since January 1, 1601).
    pub fn nt_timestamp(&self) -> u64 {
        self.0.get()
    }
}

/// 1997-01-01T00:00:00 UTC as an NTFS timestamp (100-ns intervals
/// since 1601-01-01).
pub const NTFS_TIMESTAMP_1997: u64 = 125_491_584_000_000_000;

/// 2030-01-01T00:00:00 UTC as an NTFS timestamp (100-ns intervals
/// since 1601-01-01).
pub const NTFS_TIMESTAMP_2030: u64 = 135_631_488_000_000_000;

/// Inclusive range of plausible NTFS timestamps used by recovery
/// heuristics (slack-space scanning and deleted-file scanning).
///
/// Both bounds are NTFS 100-ns ticks since 1601-01-01 UTC.
/// The default range is 1997-01-01 through 2030-01-01.
#[derive(Clone, Copy, Debug)]
pub struct TimestampBounds {
    /// Minimum plausible NTFS timestamp.
    pub min: u64,
    /// Maximum plausible NTFS timestamp.
    pub max: u64,
}

impl Default for TimestampBounds {
    fn default() -> Self {
        Self {
            min: NTFS_TIMESTAMP_1997,
            max: NTFS_TIMESTAMP_2030,
        }
    }
}

impl TimestampBounds {
    /// Returns the bounds as an inclusive range.
    pub fn range(&self) -> RangeInclusive<u64> {
        self.min..=self.max
    }

    /// Returns `true` if the given timestamp falls within the bounds.
    pub fn contains(&self, ts: u64) -> bool {
        self.range().contains(&ts)
    }

    /// Returns `true` if all four FILE_NAME timestamps are plausible.
    pub fn all_plausible(&self, timestamps: &[NtfsTime]) -> bool {
        if timestamps.is_empty() {
            return false;
        }
        timestamps.iter().all(|t| {
            let ts = t.nt_timestamp();
            ts == 0 || self.contains(ts)
        })
    }
}

impl From<u64> for NtfsTime {
    fn from(value: u64) -> Self {
        Self(U64::new(value))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsTime {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(u.arbitrary::<u64>()?))
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl<Tz: chrono::TimeZone> TryFrom<chrono::DateTime<Tz>> for NtfsTime {
    type Error = crate::error::NtfsError;

    fn try_from(dt: chrono::DateTime<Tz>) -> Result<Self, Self::Error> {
        let seconds_since_unix_epoch = dt.timestamp();
        let seconds_since_windows_epoch = seconds_since_unix_epoch
            .checked_add(EPOCH_DIFFERENCE_IN_SECONDS)
            .ok_or(crate::error::NtfsError::InvalidTime)?;
        let seconds_since_windows_epoch = u64::try_from(seconds_since_windows_epoch)
            .map_err(|_| crate::error::NtfsError::InvalidTime)?;
        let intervals_since_windows_epoch = seconds_since_windows_epoch
            .checked_mul(INTERVALS_PER_SECOND)
            .ok_or(crate::error::NtfsError::InvalidTime)?;
        let intervals_since_windows_epoch = intervals_since_windows_epoch
            .checked_add(u64::from(dt.timestamp_subsec_nanos()) / 100)
            .ok_or(crate::error::NtfsError::InvalidTime)?;

        Ok(Self::from(intervals_since_windows_epoch))
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl From<NtfsTime> for chrono::DateTime<chrono::Utc> {
    fn from(nt: NtfsTime) -> Self {
        let seconds_since_windows_epoch = (nt.nt_timestamp() / INTERVALS_PER_SECOND) as i64;
        let seconds_since_unix_epoch = seconds_since_windows_epoch - EPOCH_DIFFERENCE_IN_SECONDS;

        let subintervals = (nt.nt_timestamp() % INTERVALS_PER_SECOND) as u32;
        let subsec_nanos = subintervals * 100;

        Self::from_timestamp(seconds_since_unix_epoch, subsec_nanos).unwrap()
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<time::OffsetDateTime> for NtfsTime {
    type Error = crate::error::NtfsError;

    fn try_from(dt: time::OffsetDateTime) -> Result<Self, Self::Error> {
        let nanos_since_unix_epoch = dt.unix_timestamp_nanos();
        let intervals_since_unix_epoch = nanos_since_unix_epoch / 100;
        let intervals_since_windows_epoch =
            intervals_since_unix_epoch + i128::from(EPOCH_DIFFERENCE_IN_INTERVALS);
        let nt_timestamp = u64::try_from(intervals_since_windows_epoch)
            .map_err(|_| crate::error::NtfsError::InvalidTime)?;

        Ok(Self::from(nt_timestamp))
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl From<NtfsTime> for time::OffsetDateTime {
    fn from(nt: NtfsTime) -> time::OffsetDateTime {
        let intervals_since_windows_epoch = i128::from(nt.nt_timestamp());
        let intervals_since_unix_epoch =
            intervals_since_windows_epoch - i128::from(EPOCH_DIFFERENCE_IN_INTERVALS);
        let nanos_since_unix_epoch = intervals_since_unix_epoch * 100;

        time::OffsetDateTime::from_unix_timestamp_nanos(nanos_since_unix_epoch).unwrap()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<std::time::SystemTime> for NtfsTime {
    type Error = crate::error::NtfsError;

    fn try_from(st: std::time::SystemTime) -> Result<Self, Self::Error> {
        let duration_since_unix_epoch = st
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| crate::error::NtfsError::InvalidTime)?;
        let intervals_since_unix_epoch = duration_since_unix_epoch
            .as_secs()
            .checked_mul(INTERVALS_PER_SECOND)
            .ok_or(crate::error::NtfsError::InvalidTime)?;
        let intervals_since_unix_epoch = intervals_since_unix_epoch
            .checked_add(duration_since_unix_epoch.subsec_nanos() as u64 / 100)
            .ok_or(crate::error::NtfsError::InvalidTime)?;
        let intervals_since_windows_epoch = intervals_since_unix_epoch
            .checked_add(EPOCH_DIFFERENCE_IN_INTERVALS as u64)
            .ok_or(crate::error::NtfsError::InvalidTime)?;

        Ok(Self::from(intervals_since_windows_epoch))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const NT_TIMESTAMP_2021_01_01: u64 = 132539328000000000u64;

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_datetime() {
        let dt = chrono::DateTime::parse_from_rfc3339("2013-01-05T18:15:00Z").unwrap();
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 130018833000000000u64);

        let dt2 = chrono::DateTime::from(nt);
        assert_eq!(dt, dt2);

        // Minimum date/time supported by NT.
        let dt = chrono::DateTime::parse_from_rfc3339("1601-01-01T00:00:00Z").unwrap();
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 0u64);

        let dt = chrono::DateTime::parse_from_rfc3339("1600-12-31T23:59:59Z").unwrap();
        assert!(NtfsTime::try_from(dt).is_err());

        let dt =
            chrono::DateTime::parse_from_str("+60056-05-28 00:00:00+00", "%Y-%m-%d %T%#z").unwrap();
        assert!(NtfsTime::try_from(dt).is_ok());

        let dt =
            chrono::DateTime::parse_from_str("+60056-05-29 00:00:00+00", "%Y-%m-%d %T%#z").unwrap();
        assert!(NtfsTime::try_from(dt).is_err());
    }

    #[cfg(feature = "time")]
    #[test]
    fn test_time_offsetdatetime() {
        use time::macros::datetime;

        let dt = datetime!(2013-01-05 18:15 UTC);
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 130018833000000000u64);

        let dt2 = time::OffsetDateTime::from(nt);
        assert_eq!(dt, dt2);

        // Minimum date/time supported by NT.
        let dt = datetime!(1601-01-01 0:00 UTC);
        let nt = NtfsTime::try_from(dt).unwrap();
        assert_eq!(nt.nt_timestamp(), 0u64);

        let dt = datetime!(1600-12-31 23:59:59 UTC);
        assert!(NtfsTime::try_from(dt).is_err());

        let dt = datetime!(+60056-05-28 0:00 UTC);
        assert!(NtfsTime::try_from(dt).is_ok());

        let dt = datetime!(+60056-05-29 0:00 UTC);
        assert!(NtfsTime::try_from(dt).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_systemtime() {
        let st = std::time::SystemTime::now();
        let nt = NtfsTime::try_from(st).unwrap();
        assert!(nt.nt_timestamp() > NT_TIMESTAMP_2021_01_01);
    }

    #[test]
    fn test_timestamp_bounds_contains() {
        let bounds = TimestampBounds::default();
        // Below the lower bound (1996) is not contained.
        assert!(!bounds.contains(NTFS_TIMESTAMP_1997 - 1));
        // Exactly the lower bound is contained (inclusive).
        assert!(bounds.contains(NTFS_TIMESTAMP_1997));
        // Mid-range (2021) is contained.
        assert!(bounds.contains(NT_TIMESTAMP_2021_01_01));
        // Exactly the upper bound is contained (inclusive).
        assert!(bounds.contains(NTFS_TIMESTAMP_2030));
        // Above the upper bound is not contained.
        assert!(!bounds.contains(NTFS_TIMESTAMP_2030 + 1));
    }

    #[test]
    fn test_timestamp_bounds_custom_range() {
        // A custom narrow range distinguishes contains() from a constant.
        let bounds = TimestampBounds { min: 100, max: 200 };
        assert!(!bounds.contains(99));
        assert!(bounds.contains(100));
        assert!(bounds.contains(150));
        assert!(bounds.contains(200));
        assert!(!bounds.contains(201));
    }

    #[test]
    fn test_all_plausible() {
        let bounds = TimestampBounds::default();

        // Empty slice is never plausible.
        assert!(!bounds.all_plausible(&[]));

        // A single zero timestamp counts as plausible (the `ts == 0` arm).
        assert!(bounds.all_plausible(&[NtfsTime::from(0)]));

        // All four in-range timestamps are plausible.
        let in_range = [
            NtfsTime::from(NT_TIMESTAMP_2021_01_01),
            NtfsTime::from(NTFS_TIMESTAMP_1997),
            NtfsTime::from(NTFS_TIMESTAMP_2030),
            NtfsTime::from(0),
        ];
        assert!(bounds.all_plausible(&in_range));

        // One out-of-range nonzero timestamp makes the whole set implausible.
        // (Distinguishes `||` from `&&` and `==` from `!=` on the `ts == 0` test:
        // this value is nonzero and out of range.)
        let one_bad = [
            NtfsTime::from(NT_TIMESTAMP_2021_01_01),
            NtfsTime::from(NTFS_TIMESTAMP_2030 + 1),
        ];
        assert!(!bounds.all_plausible(&one_bad));
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_subsecond_precision() {
        // 0.0005 s = 5_000 sub-intervals (5_000 * 100 ns = 500_000 ns).
        // This exercises the `/ 100` (mutant: `% 100` / `* 100`) on the
        // sub-nanosecond path and the `* 100` reverse conversion.
        let dt = chrono::DateTime::parse_from_rfc3339("2013-01-05T18:15:00.0005Z").unwrap();
        let nt = NtfsTime::try_from(dt).unwrap();
        // 130018833000000000 (whole seconds) + 5000 sub-intervals.
        assert_eq!(nt.nt_timestamp(), 130018833000000000u64 + 5000);

        // Round-trips back to the same instant (exercises `% INTERVALS_PER_SECOND`
        // and `* 100` in the reverse direction).
        let dt2 = chrono::DateTime::<chrono::Utc>::from(nt);
        assert_eq!(dt2.timestamp_subsec_nanos(), 500_000);
        assert_eq!(dt2.timestamp(), 1357409700);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_systemtime_subsecond_precision() {
        // 1 second + 700 ns past the Unix epoch. 700 ns / 100 = 7 sub-intervals.
        // Distinguishes `/ 100` from `% 100` (700 % 100 == 0) and `* 100`.
        let st = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(1, 700);
        let nt = NtfsTime::try_from(st).unwrap();
        let expected = EPOCH_DIFFERENCE_IN_INTERVALS as u64 + INTERVALS_PER_SECOND + 7;
        assert_eq!(nt.nt_timestamp(), expected);
    }
}
