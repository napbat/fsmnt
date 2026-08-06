//! APFS timestamps.
//!
//! Every APFS timestamp is a 64-bit count of nanoseconds since the Unix epoch
//! (1970-01-01 00:00 UTC), disregarding leap seconds. This module decodes
//! that value and, behind the optional `chrono` and `time` features, converts
//! it to those crates' date-time types.
//!
//! Apple File System Reference, `07-file-system-objects.md`.

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// An APFS timestamp — nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApfsTimestamp(pub u64);

impl ApfsTimestamp {
    /// The raw nanoseconds-since-epoch value.
    #[must_use]
    pub fn nanos(self) -> u64 {
        self.0
    }

    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub fn as_secs(self) -> u64 {
        self.0 / NANOS_PER_SEC
    }

    /// The sub-second part, in nanoseconds (`0..1_000_000_000`).
    #[must_use]
    pub fn subsec_nanos(self) -> u32 {
        (self.0 % NANOS_PER_SEC) as u32
    }

    /// Whether the timestamp is unset (the epoch itself).
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Converts the timestamp to a `chrono` UTC date-time.
    ///
    /// Returns `None` if the value is out of `chrono`'s representable range.
    #[cfg(feature = "chrono")]
    #[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
    #[must_use]
    pub fn to_chrono(self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::from_timestamp(i64::try_from(self.as_secs()).ok()?, self.subsec_nanos())
    }

    /// Converts the timestamp to a `time` UTC offset date-time.
    ///
    /// Returns `None` if the value is out of `time`'s representable range.
    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    #[must_use]
    pub fn to_time(self) -> Option<time::OffsetDateTime> {
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(self.0)).ok()
    }
}

impl From<u64> for ApfsTimestamp {
    fn from(nanos: u64) -> Self {
        Self(nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_seconds_and_subsecond_nanos() {
        // 1_600_000_000.5 seconds since the epoch.
        let ts = ApfsTimestamp(1_600_000_000_500_000_000);
        assert_eq!(ts.as_secs(), 1_600_000_000);
        assert_eq!(ts.subsec_nanos(), 500_000_000);
        assert!(!ts.is_zero());
    }

    #[test]
    fn zero_is_the_epoch() {
        assert!(ApfsTimestamp(0).is_zero());
        assert_eq!(ApfsTimestamp(0).as_secs(), 0);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_conversion_matches_a_known_instant() {
        // 2020-06-22T00:00:00Z is 1_592_784_000 seconds since the epoch.
        let ts = ApfsTimestamp(1_592_784_000_000_000_000);
        let dt = ts.to_chrono().unwrap();
        assert_eq!(dt.timestamp(), 1_592_784_000);
    }

    #[cfg(feature = "time")]
    #[test]
    fn time_conversion_matches_a_known_instant() {
        let ts = ApfsTimestamp(1_592_784_000_123_456_789);
        let dt = ts.to_time().unwrap();
        assert_eq!(dt.unix_timestamp(), 1_592_784_000);
        assert_eq!(dt.nanosecond(), 123_456_789);
    }
}
