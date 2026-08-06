#[cfg(feature = "chrono")]
mod chrono_tests {
    use chrono::{DateTime, Utc};
    use fs_ext::ExtTimestamp;

    #[test]
    fn convert_positive_timestamp_to_chrono() {
        let ts = ExtTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 0,
        };
        let dt: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt.timestamp(), 1_700_000_000);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn convert_negative_timestamp_to_chrono() {
        let ts = ExtTimestamp {
            seconds: -1,
            nanoseconds: 0,
        };
        let dt: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt.timestamp(), -1);
    }

    #[test]
    fn convert_epoch_to_chrono() {
        let ts = ExtTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        let dt: DateTime<Utc> = ts.try_into().unwrap();
        assert_eq!(dt.timestamp(), 0);
    }
}

#[cfg(feature = "time")]
mod time_tests {
    use fs_ext::ExtTimestamp;
    use time::OffsetDateTime;

    #[test]
    fn convert_positive_timestamp_to_time() {
        let ts = ExtTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 0,
        };
        let dt: OffsetDateTime = ts.try_into().unwrap();
        assert_eq!(dt.unix_timestamp(), 1_700_000_000);
        assert_eq!(dt.nanosecond(), 0);
    }

    #[test]
    fn convert_negative_timestamp_to_time() {
        let ts = ExtTimestamp {
            seconds: -1,
            nanoseconds: 0,
        };
        let dt: OffsetDateTime = ts.try_into().unwrap();
        assert_eq!(dt.unix_timestamp(), -1);
    }

    #[test]
    fn convert_epoch_to_time() {
        let ts = ExtTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        let dt: OffsetDateTime = ts.try_into().unwrap();
        assert_eq!(dt.unix_timestamp(), 0);
    }
}
