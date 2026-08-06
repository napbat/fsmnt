//! exFAT timestamp handling.
//!
//! exFAT extends the DOS packed date/time format with two additional
//! fields per timestamp:
//!
//! - A **10-millisecond increment** (0-199) that refines the
//!   2-second resolution of the base DOS time.
//! - A **UTC offset** encoded as a 7-bit signed value in 15-minute
//!   increments, with a validity flag in bit 7.
//!
//! [`ExFatTimestamp`] wraps all four fields and provides typed
//! accessors plus optional conversions to `chrono` and `time` types.

/// An exFAT timestamp combining DOS date/time, 10ms increment, and
/// UTC offset.
///
/// # DOS date/time encoding
///
/// - **Date:** bits 15:9 = year since 1980, bits 8:5 = month,
///   bits 4:0 = day.
/// - **Time:** bits 15:11 = hour, bits 10:5 = minute,
///   bits 4:0 = seconds / 2.
///
/// # 10ms increment
///
/// Values 0-99 represent 0-990 ms in 10 ms steps. Values 100-199
/// add one extra second (the "odd second") plus 0-990 ms.
///
/// # UTC offset
///
/// Bit 7 is the validity flag (1 = valid). Bits 6:0 are a 7-bit
/// two's-complement signed integer giving the offset from UTC in
/// 15-minute increments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExFatTimestamp {
    /// DOS packed time.
    time: u16,
    /// DOS packed date.
    date: u16,
    /// 10-millisecond increment (0-199).
    ten_ms: u8,
    /// UTC offset byte (bit 7 = valid, bits 6:0 = signed offset).
    utc_offset: u8,
}

impl ExFatTimestamp {
    /// Creates a new timestamp with all four components.
    #[inline]
    pub const fn new(date: u16, time: u16, ten_ms: u8, utc_offset: u8) -> Self {
        Self {
            time,
            date,
            ten_ms,
            utc_offset,
        }
    }

    /// Creates a timestamp from date and time only (no 10ms
    /// increment, no UTC offset).
    ///
    /// Useful for access timestamps that lack the 10ms field.
    #[inline]
    pub const fn from_date_time(date: u16, time: u16) -> Self {
        Self {
            time,
            date,
            ten_ms: 0,
            utc_offset: 0,
        }
    }

    // --------------------------------------------------------
    // DOS date accessors
    // --------------------------------------------------------

    /// Returns the year (1980-2107).
    #[inline]
    pub const fn year(&self) -> u16 {
        1980 + ((self.date >> 9) & 0x7F)
    }

    /// Returns the month (0-12, raw extraction from date field).
    #[inline]
    pub const fn month(&self) -> u8 {
        ((self.date >> 5) & 0x0F) as u8
    }

    /// Returns the day of the month (0-31, raw extraction from
    /// date field).
    #[inline]
    pub const fn day(&self) -> u8 {
        (self.date & 0x1F) as u8
    }

    // --------------------------------------------------------
    // DOS time accessors
    // --------------------------------------------------------

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
    /// The base DOS time stores seconds / 2 (0-29). If the 10ms
    /// increment is >= 100 the odd second flag is set, adding 1.
    #[inline]
    pub const fn second(&self) -> u8 {
        let base = ((self.time & 0x1F) * 2) as u8;
        if self.ten_ms >= 100 { base + 1 } else { base }
    }

    /// Returns the millisecond component (0-990 in 10ms steps).
    ///
    /// After extracting the odd-second flag from the 10ms field,
    /// the remainder is multiplied by 10 to produce milliseconds.
    #[inline]
    pub const fn millisecond(&self) -> u16 {
        let remainder = if self.ten_ms >= 100 {
            self.ten_ms - 100
        } else {
            self.ten_ms
        };
        (remainder as u16) * 10
    }

    // --------------------------------------------------------
    // 10ms increment accessor
    // --------------------------------------------------------

    /// Returns the raw 10-millisecond increment value (0-199).
    #[inline]
    pub const fn ten_ms_increment(&self) -> u8 {
        self.ten_ms
    }

    // --------------------------------------------------------
    // UTC offset accessors
    // --------------------------------------------------------

    /// Returns `true` if the UTC offset field is valid (bit 7 set).
    #[inline]
    pub const fn utc_offset_valid(&self) -> bool {
        self.utc_offset & 0x80 != 0
    }

    /// Returns the UTC offset in minutes, or `None` if the offset
    /// is not valid.
    ///
    /// The 7-bit field is two's-complement: sign-extend bit 6 into
    /// a full i8, then multiply by 15 to convert quarter-hours to
    /// minutes.
    //
    // `#[mutants::skip]` covers the `|` operator at the sign-extend
    // step: `raw` is the result of `... & 0x7F`, so its top bit is
    // always 0, making `raw | 0x80` and `raw ^ 0x80` produce
    // identical bit patterns. The `| → ^` mutation is therefore
    // observationally equivalent on every possible input.
    #[cfg_attr(test, mutants::skip)]
    pub const fn utc_offset_minutes(&self) -> Option<i16> {
        if !self.utc_offset_valid() {
            return None;
        }
        let raw = (self.utc_offset & 0x7F) as i8;
        let signed = if raw & 0x40 != 0 {
            // Sign-extend: set bits 7..6 to 1
            (raw as u8 | !0x7F) as i8
        } else {
            raw
        };
        Some(signed as i16 * 15)
    }

    /// Returns the raw UTC offset byte for forensic analysis.
    #[inline]
    pub const fn utc_offset_raw(&self) -> u8 {
        self.utc_offset
    }

    // --------------------------------------------------------
    // Raw accessors
    // --------------------------------------------------------

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

    // --------------------------------------------------------
    // Feature-gated conversions
    // --------------------------------------------------------

    /// Converts this timestamp to a `chrono::DateTime<FixedOffset>`.
    ///
    /// If the UTC offset is valid, it is used as the fixed offset;
    /// otherwise UTC (offset 0) is assumed. Returns `None` if the
    /// date or time components are out of range (e.g. month = 0).
    #[cfg(feature = "chrono")]
    #[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
    pub fn to_chrono(&self) -> Option<chrono::DateTime<chrono::FixedOffset>> {
        let offset_secs = self.utc_offset_minutes().unwrap_or(0) as i32 * 60;
        let fo = chrono::FixedOffset::east_opt(offset_secs)?;

        let nd = chrono::NaiveDate::from_ymd_opt(
            self.year() as i32,
            self.month() as u32,
            self.day() as u32,
        )?;
        let nt = chrono::NaiveTime::from_hms_milli_opt(
            self.hour() as u32,
            self.minute() as u32,
            self.second() as u32,
            self.millisecond() as u32,
        )?;
        let ndt = chrono::NaiveDateTime::new(nd, nt);

        ndt.and_local_timezone(fo).single()
    }

    /// Converts this timestamp to a `time::OffsetDateTime`.
    ///
    /// If the UTC offset is valid, it is used; otherwise UTC
    /// (offset 0) is assumed. Returns `None` if the date or time
    /// components are out of range.
    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    pub fn to_time(&self) -> Option<time::OffsetDateTime> {
        let offset_secs = self.utc_offset_minutes().unwrap_or(0) as i32 * 60;
        let uo = time::UtcOffset::from_whole_seconds(offset_secs).ok()?;

        let month = time::Month::try_from(self.month()).ok()?;
        let date = time::Date::from_calendar_date(self.year() as i32, month, self.day()).ok()?;
        let t = time::Time::from_hms_milli(
            self.hour(),
            self.minute(),
            self.second(),
            self.millisecond(),
        )
        .ok()?;

        Some(time::OffsetDateTime::new_in_offset(date, t, uo))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_timestamp_2024_06_15() {
        // 2024-06-15 14:30:22.500
        // Year offset: 2024 - 1980 = 44
        // Date: (44 << 9) | (6 << 5) | 15 = 22528 + 192 + 15 = 0x58CF
        // Time: (14 << 11) | (30 << 5) | 11 = 28672 + 960 + 11 = 0x73CB
        //   (seconds/2 = 22/2 = 11)
        // ten_ms: 50 (0.500s = 50 * 10ms, second is even)
        // UTC+5:30 = 330min / 15 = 22 quarter-hours
        // utc_offset: 0x80 | 22 = 0x96
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 50, 0x96);

        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 6);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 14);
        assert_eq!(ts.minute(), 30);
        assert_eq!(ts.second(), 22);
        assert_eq!(ts.millisecond(), 500);
    }

    #[test]
    fn odd_second_from_ten_ms() {
        // ten_ms = 150 means odd second (1) + 50 * 10ms = 500ms
        // Base seconds from time word: 22 (11 * 2), odd second
        // adds 1 -> 23
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 150, 0);

        assert_eq!(ts.second(), 23); // 11*2 + 1 = 23
        assert_eq!(ts.millisecond(), 500); // (150 - 100) * 10
    }

    #[test]
    fn utc_offset_positive() {
        // UTC+5:30 = 330 min / 15 = 22 increments
        // utc_offset byte = 0x80 | 22 = 0x96
        let ts = ExFatTimestamp::new(0, 0, 0, 0x96);

        assert!(ts.utc_offset_valid());
        assert_eq!(ts.utc_offset_minutes(), Some(330));
    }

    #[test]
    fn utc_offset_negative() {
        // UTC-5:00 = -300 min / 15 = -20 increments
        // 7-bit two's complement of -20:
        //   -20 in binary (i8): 11101100 = 0xEC
        //   7-bit: 0xEC & 0x7F = 0x6C (108)
        // utc_offset byte = 0x80 | 0x6C = 0xEC
        let ts = ExFatTimestamp::new(0, 0, 0, 0xEC);

        assert!(ts.utc_offset_valid());
        assert_eq!(ts.utc_offset_minutes(), Some(-300));
    }

    #[test]
    fn utc_offset_invalid() {
        // bit 7 clear -> invalid
        let ts = ExFatTimestamp::new(0, 0, 0, 0x00);

        assert!(!ts.utc_offset_valid());
        assert_eq!(ts.utc_offset_minutes(), None);
    }

    #[test]
    fn zero_timestamp() {
        let ts = ExFatTimestamp::new(0, 0, 0, 0);

        assert_eq!(ts.year(), 1980);
        assert_eq!(ts.month(), 0); // raw extraction
        assert_eq!(ts.day(), 0); // raw extraction
        assert_eq!(ts.hour(), 0);
        assert_eq!(ts.minute(), 0);
        assert_eq!(ts.second(), 0);
        assert_eq!(ts.millisecond(), 0);
    }

    // --------------------------------------------------------
    // chrono feature-gated tests
    // --------------------------------------------------------

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_conversion_with_utc_offset() {
        use chrono::{Datelike, Timelike};

        // 2024-06-15 14:30:22.500 UTC+5:30
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 50, 0x96);

        let dt = ts.to_chrono().expect("valid chrono DateTime");
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 6);
        assert_eq!(dt.day(), 15);
        assert_eq!(dt.hour(), 14);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 22);
        assert_eq!(
            dt.timezone().local_minus_utc(),
            330 * 60,
            "UTC offset should be +5:30"
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_conversion_without_utc_offset() {
        use chrono::Timelike;

        // Invalid UTC offset (bit 7 clear)
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 50, 0x00);

        let dt = ts.to_chrono().expect("valid chrono DateTime");
        assert_eq!(dt.hour(), 14);
        assert_eq!(
            dt.timezone().local_minus_utc(),
            0,
            "should default to UTC when offset invalid"
        );
    }

    // --------------------------------------------------------
    // time feature-gated tests
    // --------------------------------------------------------

    #[cfg(feature = "time")]
    #[test]
    fn time_conversion_with_utc_offset() {
        // 2024-06-15 14:30:22.500 UTC+5:30
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 50, 0x96);

        let odt = ts.to_time().expect("valid time::OffsetDateTime");
        assert_eq!(odt.year(), 2024);
        assert_eq!(odt.month(), time::Month::June);
        assert_eq!(odt.day(), 15);
        assert_eq!(odt.hour(), 14);
        assert_eq!(odt.minute(), 30);
        assert_eq!(odt.second(), 22);
        assert_eq!(
            odt.offset().whole_seconds(),
            330 * 60,
            "UTC offset should be +5:30"
        );
    }

    /// Raw accessors return the stored field values. The default
    /// `make` patterns happen to use 0 or 1 for several fields, so
    /// these tests pin distinguishable non-{0,1} values to kill
    /// `→ 0` and `→ 1` constant mutations on each accessor.
    #[test]
    fn raw_accessors_return_stored_values() {
        let ts = ExFatTimestamp::new(0x58CF, 0x73CB, 50, 0x42);
        assert_eq!(ts.raw_date(), 0x58CF);
        assert_eq!(ts.raw_time(), 0x73CB);
        assert_eq!(ts.ten_ms_increment(), 50);
        assert_eq!(ts.utc_offset_raw(), 0x42);
    }

    #[cfg(feature = "time")]
    #[test]
    fn time_conversion_without_utc_offset() {
        // Invalid UTC offset (bit 7 clear)
        let date: u16 = (44 << 9) | (6 << 5) | 15;
        let time: u16 = (14 << 11) | (30 << 5) | 11;
        let ts = ExFatTimestamp::new(date, time, 50, 0x00);

        let odt = ts.to_time().expect("valid time::OffsetDateTime");
        assert_eq!(odt.hour(), 14);
        assert_eq!(
            odt.offset().whole_seconds(),
            0,
            "should default to UTC when offset invalid"
        );
    }
}
