/// Decoded ext timestamp: seconds + optional nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtTimestamp {
    /// Seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    ///
    /// Negative values represent dates before the epoch.
    /// With base timestamps only, range is -2^31 to 2^31-1
    /// (1901-12-13 to 2038-01-19).
    pub seconds: i64,
    /// Sub-second nanosecond component.
    ///
    /// Typically in range 0..999_999_999. Out-of-range values from
    /// malformed extended fields are preserved raw without clamping.
    pub nanoseconds: u32,
}

/// Decode a base 32-bit ext timestamp.
///
/// Treats `raw` as a signed 32-bit seconds value since the Unix epoch.
/// Nanoseconds are set to 0 (no extended timestamp fields in Phase 1).
pub(crate) fn base_timestamp(raw: u32) -> ExtTimestamp {
    ExtTimestamp {
        seconds: raw as i32 as i64,
        nanoseconds: 0,
    }
}

/// Decode an extended ext4 timestamp with epoch bits and nanosecond precision.
///
/// Matches `ext4_decode_extra_time` from the Linux kernel:
/// - `base`: raw 32-bit timestamp field (sign-extended to i64 before adding epoch)
/// - `extra`: low 2 bits are epoch bits; upper 30 bits are nanoseconds
///
/// No clamping or validation is performed — out-of-range nanoseconds are
/// preserved as-is.
pub(crate) fn decode_extended_timestamp(base: u32, extra: u32) -> ExtTimestamp {
    ExtTimestamp {
        seconds: (base as i32 as i64) + (((extra & 0x3) as i64) << 32),
        nanoseconds: extra >> 2,
    }
}

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl TryFrom<ExtTimestamp> for chrono::DateTime<chrono::Utc> {
    type Error = crate::error::ExtError;

    fn try_from(ts: ExtTimestamp) -> core::result::Result<Self, Self::Error> {
        if ts.nanoseconds >= 1_000_000_000 {
            return Err(crate::error::ExtError::TimestampOutOfRange);
        }
        chrono::DateTime::from_timestamp(ts.seconds, ts.nanoseconds)
            .ok_or(crate::error::ExtError::TimestampOutOfRange)
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<ExtTimestamp> for time::OffsetDateTime {
    type Error = crate::error::ExtError;

    fn try_from(ts: ExtTimestamp) -> core::result::Result<Self, Self::Error> {
        if ts.nanoseconds >= 1_000_000_000 {
            return Err(crate::error::ExtError::TimestampOutOfRange);
        }
        time::OffsetDateTime::from_unix_timestamp_nanos(
            i128::from(ts.seconds) * 1_000_000_000 + i128::from(ts.nanoseconds),
        )
        .map_err(|_| crate::error::ExtError::TimestampOutOfRange)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extended_timestamp tests ─────────────────────────────────────────────

    #[test]
    fn extended_timestamp_epoch0_positive_base() {
        // base = 100, extra = 0 (epoch 0, no nanoseconds)
        // seconds = 100 + (0 << 32) = 100
        let ts = decode_extended_timestamp(100, 0);
        assert_eq!(ts.seconds, 100);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn extended_timestamp_epoch0_negative_base() {
        // base = 0xFFFF_FFFF (-1 as i32), extra = 0 (epoch 0)
        // seconds = -1 + (0 << 32) = -1
        let ts = decode_extended_timestamp(0xFFFF_FFFF, 0);
        assert_eq!(ts.seconds, -1);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn extended_timestamp_epoch1_negative_base() {
        // base = 0x8000_0000 (-2147483648 as i32), extra = 0x01 (epoch 1)
        // seconds = -2147483648 + (1 << 32) = -2147483648 + 4294967296 = 2147483648
        let ts = decode_extended_timestamp(0x8000_0000, 0x01);
        assert_eq!(ts.seconds, 2_147_483_648_i64);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn extended_timestamp_epoch2_nanoseconds() {
        // extra = (500_000_000 << 2) | 2 → epoch 2, ns = 500_000_000
        // base = 0, seconds = 0 + (2 << 32) = 8589934592
        let ns: u32 = 500_000_000;
        let extra: u32 = (ns << 2) | 2;
        let ts = decode_extended_timestamp(0, extra);
        assert_eq!(ts.seconds, 2_i64 << 32);
        assert_eq!(ts.nanoseconds, ns);
    }

    #[test]
    fn extended_timestamp_epoch3_max_range() {
        // epoch 3 is the maximum (bits 0..=1 = 0b11), base = max positive i32
        // seconds = 2147483647 + (3 << 32) = 2147483647 + 12884901888 = 15032385535
        let ts = decode_extended_timestamp(0x7FFF_FFFF, 0x03);
        assert_eq!(ts.seconds, 2_147_483_647_i64 + (3_i64 << 32));
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn extended_timestamp_malformed_nanoseconds_preserved_raw() {
        // nanoseconds > 999_999_999 should be preserved as-is (no clamping).
        // Use extra = 0xFFFF_FFFC (epoch 0, ns bits all set) so ns = 0xFFFF_FFFF >> 2
        // = 1_073_741_823, which exceeds 999_999_999 and fits without overflow.
        let extra: u32 = 0xFFFF_FFFC; // epoch bits = 0, ns = 0x3FFF_FFFF
        let expected_ns = extra >> 2; // 1_073_741_823
        let ts = decode_extended_timestamp(0, extra);
        assert_eq!(ts.nanoseconds, expected_ns);
        assert_eq!(ts.seconds, 0);
    }

    // ── base_timestamp tests ─────────────────────────────────────────────────

    #[test]
    fn zero_timestamp() {
        let ts = base_timestamp(0);
        assert_eq!(ts.seconds, 0);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn positive_timestamp() {
        let ts = base_timestamp(1_700_000_000);
        assert_eq!(ts.seconds, 1_700_000_000);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn negative_timestamp() {
        // 0xFFFF_FFFF as u32 = -1 as i32
        let ts = base_timestamp(0xFFFF_FFFF);
        assert_eq!(ts.seconds, -1);
        assert_eq!(ts.nanoseconds, 0);
    }

    #[test]
    fn min_signed_timestamp() {
        // 0x8000_0000 as u32 = -2147483648 as i32 (1901-12-13)
        let ts = base_timestamp(0x8000_0000);
        assert_eq!(ts.seconds, -2_147_483_648);
    }

    #[test]
    fn max_signed_timestamp() {
        // 0x7FFF_FFFF as u32 = 2147483647 as i32 (2038-01-19)
        let ts = base_timestamp(0x7FFF_FFFF);
        assert_eq!(ts.seconds, 2_147_483_647);
    }
}
