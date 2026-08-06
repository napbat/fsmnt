//! FAT timestamp handling.
//!
//! FAT filesystems store timestamps in a packed DOS date/time format with 2-second resolution.
//! Creation time has additional 10ms resolution via the `create_time_tenths` field.

/// Difference in 100-nanosecond intervals between the Windows/NTFS epoch (1601-01-01)
/// and the FAT epoch (1980-01-01).
///
/// Calculated as: NTFS epoch to Unix epoch (116,444,736,000,000,000) +
/// Unix epoch to FAT epoch (3,155,328,000,000,000)
const FAT_EPOCH_DIFFERENCE_IN_INTERVALS: u64 = 119_600_064_000_000_000;

/// Number of 100-nanosecond intervals in a second.
const INTERVALS_PER_SECOND: u64 = 10_000_000;

/// Number of 100-nanosecond intervals in a millisecond.
const INTERVALS_PER_MILLISECOND: u64 = 10_000;

/// A FAT timestamp, used for expressing file times.
///
/// FAT filesystems store timestamps as packed 16-bit date and time values:
/// - Date: bits 0-4 = day (1-31), bits 5-8 = month (1-12), bits 9-15 = year (since 1980)
/// - Time: bits 0-4 = seconds/2 (0-29), bits 5-10 = minutes (0-59), bits 11-15 = hours (0-23)
///
/// Creation time has additional 10ms resolution via the `tenths` field (0-199).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FatTime {
    /// DOS date (packed format).
    date: u16,
    /// DOS time (packed format).
    time: u16,
    /// Creation time tenths of a second (0-199).
    /// Values 0-99 represent 0-990ms, values 100-199 add 1 second + 0-990ms.
    tenths: u8,
}

impl FatTime {
    /// Creates a new `FatTime` from DOS date, time, and tenths values.
    #[inline]
    pub const fn new(date: u16, time: u16, tenths: u8) -> Self {
        Self { date, time, tenths }
    }

    /// Creates a new `FatTime` from a DOS date only (time will be 00:00:00).
    ///
    /// This is useful for the `access_date` field which has no time component.
    #[inline]
    pub const fn from_date(date: u16) -> Self {
        Self {
            date,
            time: 0,
            tenths: 0,
        }
    }

    /// Returns the year (1980-2107).
    #[inline]
    pub const fn year(&self) -> u16 {
        1980 + ((self.date >> 9) & 0x7F)
    }

    /// Returns the month (1-12).
    #[inline]
    pub const fn month(&self) -> u8 {
        ((self.date >> 5) & 0x0F) as u8
    }

    /// Returns the day of the month (1-31).
    #[inline]
    pub const fn day(&self) -> u8 {
        (self.date & 0x1F) as u8
    }

    /// Returns the hour (0-23).
    #[inline]
    pub const fn hour(&self) -> u8 {
        ((self.time >> 11) & 0x1F) as u8
    }

    /// Returns the minute (0-59).
    #[inline]
    pub const fn minute(&self) -> u8 {
        ((self.time >> 5) & 0x3F) as u8
    }

    /// Returns the second (0-59).
    ///
    /// For creation time, this includes the additional second from `tenths` if >= 100.
    #[inline]
    pub const fn second(&self) -> u8 {
        let base_seconds = ((self.time & 0x1F) * 2) as u8;
        if self.tenths >= 100 {
            base_seconds + 1
        } else {
            base_seconds
        }
    }

    /// Returns the millisecond (0-990, in 10ms increments).
    #[inline]
    pub const fn millisecond(&self) -> u16 {
        let tenths_mod = if self.tenths >= 100 {
            self.tenths - 100
        } else {
            self.tenths
        };
        (tenths_mod as u16) * 10
    }

    /// Returns the raw DOS date value.
    #[inline]
    pub const fn raw_date(&self) -> u16 {
        self.date
    }

    /// Returns the raw DOS time value.
    #[inline]
    pub const fn raw_time(&self) -> u16 {
        self.time
    }

    /// Returns the raw tenths value.
    #[inline]
    pub const fn raw_tenths(&self) -> u8 {
        self.tenths
    }

    /// Returns the stored timestamp as an NT timestamp (number of 100-nanosecond intervals
    /// since January 1, 1601).
    ///
    /// This is useful for compatibility with NTFS timestamps.
    pub fn nt_timestamp(&self) -> u64 {
        // Calculate days since FAT epoch (1980-01-01)
        let days = self.days_since_fat_epoch();

        // Calculate seconds within the day
        let seconds_in_day =
            (self.hour() as u64) * 3600 + (self.minute() as u64) * 60 + (self.second() as u64);

        // Calculate total seconds since FAT epoch
        let total_seconds = (days as u64) * 86400 + seconds_in_day;

        // Convert to 100-nanosecond intervals and add FAT epoch offset
        let intervals = total_seconds * INTERVALS_PER_SECOND
            + (self.millisecond() as u64) * INTERVALS_PER_MILLISECOND;

        FAT_EPOCH_DIFFERENCE_IN_INTERVALS + intervals
    }

    /// Calculates the number of days since the FAT epoch (1980-01-01).
    fn days_since_fat_epoch(&self) -> u32 {
        let year = self.year() as u32;
        let month = self.month() as u32;
        let day = self.day() as u32;

        // Years since 1980
        let years_since_epoch = year - 1980;

        // Count leap years from 1980 to year-1
        let leap_years = Self::count_leap_years(1980, year);

        // Days from complete years
        let days_from_years = years_since_epoch * 365 + leap_years;

        // Days from complete months in current year
        let days_from_months = Self::days_before_month(month, Self::is_leap_year(year));

        // Total days (day is 1-based, so subtract 1)
        days_from_years + days_from_months + day.saturating_sub(1)
    }

    /// Counts leap years in the range [start_year, end_year).
    fn count_leap_years(start_year: u32, end_year: u32) -> u32 {
        if end_year <= start_year {
            return 0;
        }

        let count_before = |year: u32| -> u32 {
            if year == 0 {
                return 0;
            }
            let y = year - 1;
            y / 4 - y / 100 + y / 400
        };

        count_before(end_year) - count_before(start_year)
    }

    /// Returns true if the given year is a leap year.
    const fn is_leap_year(year: u32) -> bool {
        (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
    }

    /// Returns the number of days before the given month (1-12) in a year.
    const fn days_before_month(month: u32, is_leap: bool) -> u32 {
        const DAYS_BEFORE: [u32; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        const DAYS_BEFORE_LEAP: [u32; 13] =
            [0, 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];

        if month > 12 {
            return 0;
        }

        if is_leap {
            DAYS_BEFORE_LEAP[month as usize]
        } else {
            DAYS_BEFORE[month as usize]
        }
    }
}

impl Default for FatTime {
    fn default() -> Self {
        // Default to FAT epoch: 1980-01-01 00:00:00
        Self::new(0x0021, 0, 0) // date = (0 << 9) | (1 << 5) | 1 = 0x21
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl From<FatTime> for chrono::DateTime<chrono::Utc> {
    fn from(fat: FatTime) -> Self {
        use chrono::{TimeZone, Utc};

        Utc.with_ymd_and_hms(
            fat.year() as i32,
            fat.month() as u32,
            fat.day() as u32,
            fat.hour() as u32,
            fat.minute() as u32,
            fat.second() as u32,
        )
        .single()
        .map(|dt| dt + chrono::Duration::milliseconds(fat.millisecond() as i64))
        .unwrap_or_else(|| Utc.with_ymd_and_hms(1980, 1, 1, 0, 0, 0).unwrap())
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl<Tz: chrono::TimeZone> TryFrom<chrono::DateTime<Tz>> for FatTime {
    type Error = crate::error::FatError;

    // `|` vs `^` on the DOS date/time bit-packing is an equivalent
    // mutation: each `<<` shifts its argument into a disjoint bit range
    // (year_offset → 9..15, month → 5..8, day → 0..4; hour → 11..15,
    // minute → 5..10, second/2 → 0..4), so OR and XOR produce the same
    // value for every legal input. cargo-mutants enumerates these
    // anyway; skip the whole function rather than write a contrived
    // test that pretends to distinguish them.
    #[cfg_attr(test, mutants::skip)]
    fn try_from(dt: chrono::DateTime<Tz>) -> Result<Self, Self::Error> {
        use chrono::{Datelike, Timelike};

        let year = dt.year();
        let month = dt.month();
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        let second = dt.second();
        let millis = dt.timestamp_subsec_millis();

        // Validate FAT date range (1980-2107)
        if !(1980..=2107).contains(&year) {
            return Err(crate::error::FatError::InvalidTime);
        }

        let year_offset = (year - 1980) as u16;
        let date = (year_offset << 9) | ((month as u16) << 5) | (day as u16);
        let time = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second / 2) as u16);

        // Calculate tenths: odd seconds add 100, plus milliseconds / 10
        // Clamp to 99 to ensure the result fits in the valid range (0-199)
        let tenths = if second % 2 == 1 { 100 } else { 0 } + (millis / 10).min(99) as u8;

        Ok(Self::new(date, time, tenths))
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<FatTime> for time::OffsetDateTime {
    type Error = time::error::ComponentRange;

    fn try_from(fat: FatTime) -> Result<Self, Self::Error> {
        let date = time::Date::from_calendar_date(
            fat.year() as i32,
            time::Month::try_from(fat.month())?,
            fat.day(),
        )?;
        let time_val =
            time::Time::from_hms_milli(fat.hour(), fat.minute(), fat.second(), fat.millisecond())?;
        Ok(time::OffsetDateTime::new_utc(date, time_val))
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<time::OffsetDateTime> for FatTime {
    type Error = crate::error::FatError;

    // Same `|` vs `^` equivalence as the chrono impl: each `<<` lands in a
    // disjoint bit range, so OR and XOR are indistinguishable.
    #[cfg_attr(test, mutants::skip)]
    fn try_from(dt: time::OffsetDateTime) -> Result<Self, Self::Error> {
        let year = dt.year();
        let month = dt.month() as u8;
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        let second = dt.second();
        let millis = dt.millisecond();

        // Validate FAT date range (1980-2107)
        if !(1980..=2107).contains(&year) {
            return Err(crate::error::FatError::InvalidTime);
        }

        let year_offset = (year - 1980) as u16;
        let date = (year_offset << 9) | ((month as u16) << 5) | (day as u16);
        let time = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second / 2) as u16);

        // Calculate tenths: odd seconds add 100, plus milliseconds / 10
        // Clamp to 99 to ensure the result fits in the valid range (0-199)
        let tenths = if second % 2 == 1 { 100 } else { 0 } + (millis / 10).min(99) as u8;

        Ok(Self::new(date, time, tenths))
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<std::time::SystemTime> for FatTime {
    type Error = crate::error::FatError;

    // The final `|` chains that pack the DOS date/time fields are
    // equivalent under `| → ^` because each operand sits in a disjoint
    // bit range (see the chrono impl above for the analysis). All
    // other arithmetic in this function — including the FAT-epoch
    // lower bound and the year=2107 upper bound — is anchored by the
    // tests in the `tests` module.
    #[cfg_attr(test, mutants::skip)]
    fn try_from(st: std::time::SystemTime) -> Result<Self, Self::Error> {
        // Calculate duration since FAT epoch (1980-01-01)
        // FAT epoch is 315,532,800 seconds after Unix epoch (1970-01-01)
        const FAT_EPOCH_UNIX_SECONDS: u64 = 315_532_800;

        let duration_since_unix = st
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| crate::error::FatError::InvalidTime)?;

        let secs_since_unix = duration_since_unix.as_secs();
        if secs_since_unix < FAT_EPOCH_UNIX_SECONDS {
            return Err(crate::error::FatError::InvalidTime);
        }

        let secs_since_fat = secs_since_unix - FAT_EPOCH_UNIX_SECONDS;
        let millis = (duration_since_unix.subsec_millis()) as u16;

        // Convert seconds to date/time components
        let days = secs_since_fat / 86400;
        let time_of_day = secs_since_fat % 86400;

        let hour = (time_of_day / 3600) as u8;
        let minute = ((time_of_day % 3600) / 60) as u8;
        let second = (time_of_day % 60) as u8;

        // Convert days to year/month/day
        let (year, month, day) = Self::days_to_ymd(days as u32);

        if year > 2107 {
            return Err(crate::error::FatError::InvalidTime);
        }

        let year_offset = (year - 1980) as u16;
        let date = (year_offset << 9) | ((month as u16) << 5) | (day as u16);
        let time = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second / 2) as u16);

        // Calculate tenths: odd seconds add 100, plus milliseconds / 10
        // Clamp to 99 to ensure the result fits in the valid range (0-199)
        let tenths = if second % 2 == 1 { 100 } else { 0 } + ((millis / 10).min(99)) as u8;

        Ok(Self::new(date, time, tenths))
    }
}

#[cfg(feature = "std")]
impl FatTime {
    /// Converts days since FAT epoch to (year, month, day).
    fn days_to_ymd(mut days: u32) -> (u32, u8, u8) {
        // Start from 1980
        let mut year = 1980u32;

        loop {
            let days_in_year = if Self::is_leap_year(year) { 366 } else { 365 };
            if days < days_in_year {
                break;
            }
            days -= days_in_year;
            year += 1;
        }

        // Find month
        let is_leap = Self::is_leap_year(year);
        let days_in_months: [u32; 12] = if is_leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut month = 1u8;
        for &dim in &days_in_months {
            if days < dim {
                break;
            }
            days -= dim;
            month += 1;
        }

        let day = (days + 1) as u8; // days is 0-based, day is 1-based

        (year, month, day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fat_time_components() {
        // Test date: 2023-06-15 14:30:45.120
        // Year offset: 2023 - 1980 = 43
        // Date: (43 << 9) | (6 << 5) | 15 = 22016 + 192 + 15 = 0x56CF
        // Time: (14 << 11) | (30 << 5) | 22 = 28672 + 960 + 22 = 0x73D6 (22 = 45/2)
        // Tenths: 100 (odd second) + 12 (120ms / 10) = 112
        let date = ((43u16) << 9) | ((6u16) << 5) | 15u16; // 0x56CF
        let time = ((14u16) << 11) | ((30u16) << 5) | 22u16; // 0x73D6
        let fat = FatTime::new(date, time, 112);

        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 14);
        assert_eq!(fat.minute(), 30);
        assert_eq!(fat.second(), 45);
        assert_eq!(fat.millisecond(), 120);
    }

    #[test]
    fn test_fat_epoch() {
        // FAT epoch: 1980-01-01 00:00:00
        let fat = FatTime::new(0x0021, 0, 0);

        assert_eq!(fat.year(), 1980);
        assert_eq!(fat.month(), 1);
        assert_eq!(fat.day(), 1);
        assert_eq!(fat.hour(), 0);
        assert_eq!(fat.minute(), 0);
        assert_eq!(fat.second(), 0);
        assert_eq!(fat.millisecond(), 0);

        // NT timestamp should be the FAT epoch difference
        assert_eq!(fat.nt_timestamp(), FAT_EPOCH_DIFFERENCE_IN_INTERVALS);
    }

    #[test]
    fn test_from_date_only() {
        // 2023-06-15: (43 << 9) | (6 << 5) | 15 = 0x56CF
        let date = ((43u16) << 9) | ((6u16) << 5) | 15u16;
        let fat = FatTime::from_date(date);

        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 0);
        assert_eq!(fat.minute(), 0);
        assert_eq!(fat.second(), 0);
    }

    #[test]
    fn test_leap_year() {
        assert!(FatTime::is_leap_year(2000)); // Divisible by 400
        assert!(!FatTime::is_leap_year(1900)); // Divisible by 100 but not 400
        assert!(FatTime::is_leap_year(2004)); // Divisible by 4
        assert!(!FatTime::is_leap_year(2001)); // Not divisible by 4
    }

    #[test]
    fn test_nt_timestamp_known_date() {
        // 2000-01-01 00:00:00 should be a known value
        // Year offset: 2000 - 1980 = 20
        // Date: (20 << 9) | (1 << 5) | 1 = 10240 + 32 + 1 = 0x2821
        let fat = FatTime::new(0x2821, 0, 0);

        assert_eq!(fat.year(), 2000);
        assert_eq!(fat.month(), 1);
        assert_eq!(fat.day(), 1);

        // Days from 1980-01-01 to 2000-01-01:
        // 20 years with 5 leap years (1980, 1984, 1988, 1992, 1996)
        // = 20 * 365 + 5 = 7305 days
        let expected_days = 7305u64;
        let expected_intervals =
            FAT_EPOCH_DIFFERENCE_IN_INTERVALS + expected_days * 86400 * INTERVALS_PER_SECOND;
        assert_eq!(fat.nt_timestamp(), expected_intervals);
    }

    // ----------------------------------------------------------------------
    // Raw field accessors — pin against `-> u16/u8 with 0/1` mutants.
    // ----------------------------------------------------------------------

    #[test]
    fn raw_date_time_tenths_return_constructor_values() {
        // Pick distinct, non-{0,1} values so each accessor's
        // constant-replacement mutant is observable.
        let fat = FatTime::new(0x56CF, 0x73D6, 112);
        assert_eq!(fat.raw_date(), 0x56CF);
        assert_eq!(fat.raw_time(), 0x73D6);
        assert_eq!(fat.raw_tenths(), 112);

        // Boundary zero/one values must also round-trip.
        let zero = FatTime::new(0, 0, 0);
        assert_eq!(zero.raw_date(), 0);
        assert_eq!(zero.raw_time(), 0);
        assert_eq!(zero.raw_tenths(), 0);

        let one = FatTime::new(1, 1, 1);
        assert_eq!(one.raw_date(), 1);
        assert_eq!(one.raw_time(), 1);
        assert_eq!(one.raw_tenths(), 1);
    }

    // ----------------------------------------------------------------------
    // nt_timestamp arithmetic — the existing test uses midnight on
    // 2000-01-01, which leaves the time-of-day and millisecond terms at 0.
    // Mutating the additions or multiplications there is silent. The
    // tests below force a non-zero time-of-day and non-zero milliseconds
    // so every arithmetic-operator mutant becomes observable.
    // ----------------------------------------------------------------------

    #[test]
    fn nt_timestamp_includes_time_of_day_and_milliseconds() {
        // 2023-06-15 14:30:45.120 UTC.
        // Year offset = 43 (2023 - 1980).
        // Days 1980-01-01 → 2023-06-15:
        //   43 years * 365 = 15_695
        //   leap years in [1980, 2023): 1980,1984,1988,1992,1996,2000,2004,2008,2012,2016,2020
        //     = 11 leap days
        //   plus days in 2023 before June: 31+28+31+30+31 = 151 (2023 not leap)
        //   plus day-of-month - 1 = 14
        //   total = 15695 + 11 + 151 + 14 = 15871
        // seconds_in_day = 14*3600 + 30*60 + 45 = 50400 + 1800 + 45 = 52245
        // milliseconds = 120
        let date = ((43u16) << 9) | ((6u16) << 5) | 15u16; // 0x56CF
        let time = ((14u16) << 11) | ((30u16) << 5) | 22u16; // 0x73D6 (sec/2 = 22)
        let tenths = 112u8; // odd second + 12 → second 45, ms 120
        let fat = FatTime::new(date, time, tenths);

        // Sanity: components decode correctly.
        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.second(), 45);
        assert_eq!(fat.millisecond(), 120);

        let days: u64 = 15871;
        let seconds_in_day: u64 = 14 * 3600 + 30 * 60 + 45;
        let total_seconds = days * 86400 + seconds_in_day;
        let expected = FAT_EPOCH_DIFFERENCE_IN_INTERVALS
            + total_seconds * INTERVALS_PER_SECOND
            + 120u64 * INTERVALS_PER_MILLISECOND;

        assert_eq!(fat.nt_timestamp(), expected);
        // Distinguish from the constant-replacement floor: must be strictly
        // larger than the FAT-epoch baseline.
        assert!(fat.nt_timestamp() > FAT_EPOCH_DIFFERENCE_IN_INTERVALS);
    }

    // ----------------------------------------------------------------------
    // days_since_fat_epoch — anchor the multi-arm sum.
    // ----------------------------------------------------------------------

    #[test]
    fn days_since_fat_epoch_for_known_dates() {
        // 1980-01-01: 0 days.
        let epoch = FatTime::new(0x0021, 0, 0);
        assert_eq!(epoch.days_since_fat_epoch(), 0);

        // 1980-01-02: 1 day.
        let day_2 = FatTime::new(0x0022, 0, 0);
        assert_eq!(day_2.days_since_fat_epoch(), 1);

        // 1981-01-01: 366 days (1980 was a leap year).
        let year_1981 = FatTime::new(((1u16) << 9) | (1 << 5) | 1, 0, 0);
        assert_eq!(year_1981.days_since_fat_epoch(), 366);

        // 2000-01-01: 7305 days (20 years incl 5 leap years).
        let year_2000 = FatTime::new(0x2821, 0, 0);
        assert_eq!(year_2000.days_since_fat_epoch(), 7305);

        // 2023-06-15 from the nt_timestamp test = 15871 days.
        let dt = FatTime::new(0x56CF, 0, 0);
        assert_eq!(dt.days_since_fat_epoch(), 15871);
    }

    // ----------------------------------------------------------------------
    // count_leap_years — pin both `(year-1)/X` expressions and the
    // subtraction between the two endpoints.
    // ----------------------------------------------------------------------

    #[test]
    fn count_leap_years_known_ranges() {
        // Empty range: 0.
        assert_eq!(FatTime::count_leap_years(2000, 2000), 0);
        assert_eq!(FatTime::count_leap_years(2024, 2020), 0); // end <= start

        // [1980, 1981) → 1980 itself is a leap year → 1.
        assert_eq!(FatTime::count_leap_years(1980, 1981), 1);

        // [1980, 2000) → 1980,84,88,92,96 = 5.
        assert_eq!(FatTime::count_leap_years(1980, 2000), 5);

        // [1980, 2001) → adds 2000 (divisible by 400) = 6.
        assert_eq!(FatTime::count_leap_years(1980, 2001), 6);

        // [1900, 2000) → 1900 is NOT a leap (div 100 but not 400),
        // so 24 leap years between 1900-1999.
        assert_eq!(FatTime::count_leap_years(1900, 2000), 24);

        // [1900, 2001) → adds 2000 = 25.
        assert_eq!(FatTime::count_leap_years(1900, 2001), 25);
    }

    // ----------------------------------------------------------------------
    // days_before_month — anchor each `>` boundary and the array lookup.
    // ----------------------------------------------------------------------

    #[test]
    fn days_before_month_matches_known_values() {
        // Catches `days_before_month -> u32 with 0` and `> with >=/==/<`
        // boundary mutations.

        // Month 0 → 0 (sentinel).
        assert_eq!(FatTime::days_before_month(0, false), 0);
        assert_eq!(FatTime::days_before_month(0, true), 0);

        // Month 1 (January) → 0 days before.
        assert_eq!(FatTime::days_before_month(1, false), 0);
        assert_eq!(FatTime::days_before_month(1, true), 0);

        // Month 3 (March) — leap-year differs from non-leap.
        assert_eq!(FatTime::days_before_month(3, false), 59); // 31 + 28
        assert_eq!(FatTime::days_before_month(3, true), 60); // 31 + 29

        // Month 12 (December).
        assert_eq!(FatTime::days_before_month(12, false), 334);
        assert_eq!(FatTime::days_before_month(12, true), 335);

        // Month 13 → 0 (out of range, anchors the `> 12` guard).
        assert_eq!(FatTime::days_before_month(13, false), 0);
        // Month 100 also out of range.
        assert_eq!(FatTime::days_before_month(100, false), 0);
    }

    // ----------------------------------------------------------------------
    // days_to_ymd — the std-only inverse used by SystemTime conversion.
    // Anchor each of the multi-byte tuple-replacement mutants by asserting
    // the returned (y, m, d) on multiple known days. Also anchors the two
    // `< with X` boundary mutants and the `-= / += with */-/=` swaps.
    // ----------------------------------------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn days_to_ymd_round_trip_for_known_dates() {
        // 0 days → 1980-01-01.
        assert_eq!(FatTime::days_to_ymd(0), (1980, 1, 1));

        // 1 day → 1980-01-02 (anchors the day "+1" finalize).
        assert_eq!(FatTime::days_to_ymd(1), (1980, 1, 2));

        // 31 days → 1980-02-01 (crosses month boundary in a leap year).
        assert_eq!(FatTime::days_to_ymd(31), (1980, 2, 1));

        // 59 days → 1980-02-29 (leap year leftover).
        assert_eq!(FatTime::days_to_ymd(59), (1980, 2, 29));

        // 60 days → 1980-03-01 (crosses Feb→Mar in leap year).
        assert_eq!(FatTime::days_to_ymd(60), (1980, 3, 1));

        // 365 days → 1980-12-31 (last day of leap 1980).
        assert_eq!(FatTime::days_to_ymd(365), (1980, 12, 31));

        // 366 days → 1981-01-01.
        assert_eq!(FatTime::days_to_ymd(366), (1981, 1, 1));

        // 7305 days → 2000-01-01.
        assert_eq!(FatTime::days_to_ymd(7305), (2000, 1, 1));

        // 15871 days → 2023-06-15 (matches nt_timestamp test).
        assert_eq!(FatTime::days_to_ymd(15871), (2023, 6, 15));
    }

    // ----------------------------------------------------------------------
    // Chrono conversions — round-trip a date with non-trivial time and
    // millisecond components. These pin the date/time bit-packing in
    // TryFrom<chrono::DateTime> for FatTime and the From<FatTime> branch.
    // ----------------------------------------------------------------------

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_from_fat_time_preserves_date_time_and_milliseconds() {
        use chrono::{Datelike, Timelike};

        let date = ((43u16) << 9) | ((6u16) << 5) | 15u16;
        let time = ((14u16) << 11) | ((30u16) << 5) | 22u16;
        let fat = FatTime::new(date, time, 112);

        let dt: chrono::DateTime<chrono::Utc> = fat.into();
        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 6);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 14);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 45);
        assert_eq!(dt.timestamp_subsec_millis(), 120);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_try_from_round_trips_through_fat_time() {
        use chrono::{TimeZone, Utc};

        let original = Utc
            .with_ymd_and_hms(2023, 6, 15, 14, 30, 45)
            .unwrap()
            .checked_add_signed(chrono::Duration::milliseconds(120))
            .unwrap();

        let fat: FatTime = FatTime::try_from(original).unwrap();
        // Bit-packing must round-trip identically.
        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 14);
        assert_eq!(fat.minute(), 30);
        assert_eq!(fat.second(), 45);
        assert_eq!(fat.millisecond(), 120);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_try_from_rejects_out_of_range_year() {
        use chrono::{TimeZone, Utc};

        let too_early = Utc.with_ymd_and_hms(1979, 12, 31, 23, 59, 59).unwrap();
        assert!(FatTime::try_from(too_early).is_err());

        let too_late = Utc.with_ymd_and_hms(2108, 1, 1, 0, 0, 0).unwrap();
        assert!(FatTime::try_from(too_late).is_err());

        // Boundary years that ARE valid.
        let earliest = Utc.with_ymd_and_hms(1980, 1, 1, 0, 0, 0).unwrap();
        assert!(FatTime::try_from(earliest).is_ok());

        let latest = Utc.with_ymd_and_hms(2107, 12, 31, 23, 59, 58).unwrap();
        assert!(FatTime::try_from(latest).is_ok());
    }

    // ----------------------------------------------------------------------
    // time crate conversions.
    // ----------------------------------------------------------------------

    #[cfg(feature = "time")]
    fn build_offset_dt(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        millisecond: u16,
    ) -> time::OffsetDateTime {
        let date = time::Date::from_calendar_date(year, time::Month::try_from(month).unwrap(), day)
            .unwrap();
        let t = time::Time::from_hms_milli(hour, minute, second, millisecond).unwrap();
        time::OffsetDateTime::new_utc(date, t)
    }

    #[cfg(feature = "time")]
    #[test]
    fn time_offset_date_time_round_trips_through_fat_time() {
        let original = build_offset_dt(2023, 6, 15, 14, 30, 45, 120);

        let fat: FatTime = FatTime::try_from(original).unwrap();
        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 14);
        assert_eq!(fat.minute(), 30);
        assert_eq!(fat.second(), 45);
        assert_eq!(fat.millisecond(), 120);

        let back: time::OffsetDateTime = fat.try_into().unwrap();
        assert_eq!(back, original);
    }

    #[cfg(feature = "time")]
    #[test]
    fn time_try_from_fat_time_rejects_out_of_range_year() {
        let too_early = build_offset_dt(1979, 12, 31, 23, 59, 58, 0);
        assert!(FatTime::try_from(too_early).is_err());

        let too_late = build_offset_dt(2108, 1, 1, 0, 0, 0, 0);
        assert!(FatTime::try_from(too_late).is_err());

        let earliest = build_offset_dt(1980, 1, 1, 0, 0, 0, 0);
        assert!(FatTime::try_from(earliest).is_ok());

        let latest = build_offset_dt(2107, 12, 31, 23, 59, 58, 0);
        assert!(FatTime::try_from(latest).is_ok());
    }

    // ----------------------------------------------------------------------
    // SystemTime conversion (std-only).
    // ----------------------------------------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn system_time_try_from_round_trip() {
        use std::time::{Duration, UNIX_EPOCH};

        // 2023-06-15 14:30:45.120 UTC in seconds since Unix epoch.
        // FAT epoch = 1980-01-01 = 315_532_800 seconds after Unix epoch.
        // (2023-06-15 14:30:45) seconds since Unix epoch:
        //   days from 1980-01-01 = 15871 (verified above)
        //   total seconds since FAT = 15871 * 86400 + 14*3600 + 30*60 + 45
        //                           = 1_371_254_400 + 52_245 = 1_371_306_645
        //   plus FAT_EPOCH_UNIX_SECONDS = 1_686_839_445
        let st = UNIX_EPOCH + Duration::from_secs(1_686_839_445) + Duration::from_millis(120);

        let fat = FatTime::try_from(st).unwrap();
        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 14);
        assert_eq!(fat.minute(), 30);
        assert_eq!(fat.second(), 45);
        assert_eq!(fat.millisecond(), 120);
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_time_before_fat_epoch_returns_invalid_time() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // 1979-12-31 23:59:59 UTC — one second before FAT epoch.
        let st = UNIX_EPOCH + Duration::from_secs(315_532_800 - 1);
        let err = FatTime::try_from(st).unwrap_err();
        assert!(matches!(err, crate::error::FatError::InvalidTime));

        // 1970-01-01 00:00:00 UTC (Unix epoch) is also pre-FAT.
        let unix_epoch = SystemTime::UNIX_EPOCH;
        let err = FatTime::try_from(unix_epoch).unwrap_err();
        assert!(matches!(err, crate::error::FatError::InvalidTime));
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_time_at_or_after_2108_returns_invalid_time() {
        use std::time::{Duration, UNIX_EPOCH};

        // 2108-01-01 00:00:00 UTC. days from 1980 = 128 years.
        // leap years in [1980, 2108): 1980,84,..,2000,..,2104 = 32
        //   (1980-step-of-4 = (2108-1980)/4 = 32 incl 2100 — but 2100
        //   isn't a leap year, so 31. Plus 2000 is leap, so 31 total.)
        // Simpler: just pick a clearly out-of-range value.
        let years_after_fat_epoch = 130u64;
        let st =
            UNIX_EPOCH + Duration::from_secs(315_532_800 + years_after_fat_epoch * 365 * 86400);
        let err = FatTime::try_from(st).unwrap_err();
        assert!(matches!(err, crate::error::FatError::InvalidTime));
    }

    // ------------------------------------------------------------------
    // Boundary tests that exercise the exact `<` / `>` thresholds in
    // SystemTime conversion. Anchors `< with <=` at line 336 (the
    // FAT-epoch lower bound) and `> with >=` at line 354 (the 2107
    // upper bound).
    // ------------------------------------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn system_time_exactly_at_fat_epoch_returns_ok() {
        use std::time::{Duration, UNIX_EPOCH};

        // FAT_EPOCH_UNIX_SECONDS = 315_532_800 = 1980-01-01 00:00:00 UTC.
        // Original `if secs < FAT_EPOCH` rejects strictly-before; the
        // FAT-epoch second itself must succeed.
        let st = UNIX_EPOCH + Duration::from_secs(315_532_800);
        let fat = FatTime::try_from(st).unwrap();
        assert_eq!(fat.year(), 1980);
        assert_eq!(fat.month(), 1);
        assert_eq!(fat.day(), 1);
        assert_eq!(fat.hour(), 0);
        assert_eq!(fat.minute(), 0);
        assert_eq!(fat.second(), 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_time_year_2107_january_first_is_accepted() {
        use std::time::{Duration, UNIX_EPOCH};

        // 127 years × 365 + 31 leap days = 46_386 days from 1980-01-01.
        // (Leap years: 1980,84,...,2104 = 32 entries, minus 2100 (not leap)
        // = 31 leap days.)
        // secs_since_fat = 46_386 × 86_400 = 4_007_750_400.
        // secs_since_unix = 4_007_750_400 + 315_532_800 = 4_323_283_200.
        let st = UNIX_EPOCH + Duration::from_secs(4_323_283_200);
        let fat = FatTime::try_from(st).unwrap();
        assert_eq!(fat.year(), 2107);
        assert_eq!(fat.month(), 1);
        assert_eq!(fat.day(), 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_time_at_midnight_packs_hour_zero() {
        use std::time::{Duration, UNIX_EPOCH};

        // Midnight on 2023-06-15. With hour=0, mutating `% 86400` →
        // `+ 86400` makes the derived hour wrap into 24 instead of 0,
        // which decodes back as fat.hour() = 24 (vs the original 0).
        // Without a midnight fixture, the truncation to u8 can mask
        // the `+ 86400` mutation when the upstream calculation lands
        // on the same low byte.
        let st = UNIX_EPOCH + Duration::from_secs(1_686_787_200); // 2023-06-15 00:00:00
        let fat = FatTime::try_from(st).unwrap();
        assert_eq!(fat.year(), 2023);
        assert_eq!(fat.month(), 6);
        assert_eq!(fat.day(), 15);
        assert_eq!(fat.hour(), 0);
        assert_eq!(fat.minute(), 0);
        assert_eq!(fat.second(), 0);
    }
}
