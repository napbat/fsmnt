//! Timestamp anomaly detection for identifying timestomping.
//!
//! Timestomping is an anti-forensic technique where attackers modify file
//! timestamps to blend malicious files with legitimate ones. NTFS stores
//! timestamps in two attributes:
//!
//! - **`$STANDARD_INFORMATION` (0x10)**: Modifiable by user-mode APIs
//!   (`SetFileTime`). Attackers typically change these.
//! - **`$FILE_NAME` (0x30)**: Only modifiable by the kernel. Cannot be
//!   changed without raw disk access.
//!
//! Comparing the two reveals manipulation. This module provides structured
//! analysis results with individual heuristic flags so callers can weight
//! them according to their use case.
//!
//! # Caveats
//!
//! - `$FILE_NAME` timestamps are only updated when the filename changes
//!   (rename, move, hard-link creation). They can be legitimately stale.
//! - `$FILE_NAME` creation time reflects directory entry creation, not
//!   necessarily file birth. Copy and move operations can produce
//!   legitimate discrepancies.
//! - These heuristics flag *suspicious* patterns, not definitive proof
//!   of tampering. Always correlate with other forensic artifacts.
//!
//! # References
//!
//! - [MITRE ATT&CK T1070.006 — Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
//! - [InverseCos: Timestomping Detection](https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html)

use crate::structured_values::{NtfsFileName, NtfsStandardInformation};
use crate::time::NtfsTime;

/// Number of 100-nanosecond intervals in one second.
const INTERVALS_PER_SECOND: u64 = 10_000_000;

/// Number of 100-nanosecond intervals in one minute.
const INTERVALS_PER_MINUTE: u64 = 60 * INTERVALS_PER_SECOND;

/// Default threshold for the `mft_modified_much_newer` heuristic: 30 days
/// in 100-nanosecond intervals.
///
/// If the MFT record modification time exceeds the latest of
/// `$SI.created` and `$SI.modified` by more than this value, the
/// heuristic triggers. Callers who need a different threshold can use
/// [`detect_timestamp_anomalies_with_threshold`].
pub const DEFAULT_MFT_MODIFIED_THRESHOLD: u64 = 30 * 24 * 3_600 * INTERVALS_PER_SECOND;

/// Results of timestamp anomaly analysis comparing `$STANDARD_INFORMATION`
/// and `$FILE_NAME` attributes.
///
/// Each boolean field represents an independent heuristic. Callers should
/// weight them according to their investigative context — no single flag
/// is definitive proof of timestomping.
///
/// All timestamp fields are included so callers can perform additional
/// analysis beyond the built-in heuristics.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct NtfsTimestampAnomaly {
    // -- Heuristic flags --------------------------------------------------
    /// `$SI` creation time is earlier than `$FN` creation time.
    ///
    /// Strong indicator that `$SI` creation was backdated, since `$FN`
    /// creation is kernel-managed. However, legitimate discrepancies can
    /// occur after rename/move/copy operations.
    pub si_created_before_fn_created: bool,

    /// `$SI` modification time is earlier than `$FN` creation time.
    ///
    /// Suggests `$SI` modification was backdated to before the directory
    /// entry was created. Weaker than `si_created_before_fn_created`
    /// because `$FN` creation time reflects directory entry creation,
    /// not necessarily file birth.
    pub si_modified_before_fn_created: bool,

    /// All four `$SI` timestamps have zero sub-second precision
    /// (i.e., `nt_timestamp % 10_000_000 == 0`).
    ///
    /// NTFS natively records timestamps at 100ns resolution. Many
    /// timestomping tools set only second-precision values, producing
    /// this pattern. Legitimate software occasionally does this too
    /// (e.g., ZIP extraction, some installers).
    pub si_second_precision: bool,

    /// All four `$SI` timestamps are identical.
    ///
    /// Legitimate files rarely have all four timestamps match exactly.
    /// Common with bulk timestamp-setting tools.
    pub si_all_timestamps_identical: bool,

    /// All four `$SI` timestamps are aligned to minute or hour
    /// boundaries.
    ///
    /// Programmatic timestamp setting often uses round values (e.g.,
    /// midnight, top of the hour). This is a superset of
    /// `si_second_precision` — if timestamps are minute/hour-aligned,
    /// they are also second-aligned.
    pub si_rounded_to_minute_or_hour: bool,

    /// `$SI` MFT record modification time is much newer than the
    /// latest of `$SI` creation and modification times.
    ///
    /// Indicates the MFT entry was recently touched while the file
    /// appears old. Can also trigger from legitimate metadata updates
    /// (ACL changes, AV scanning, moves). Use
    /// [`detect_timestamp_anomalies_with_threshold`] to customize the
    /// threshold (default: 30 days).
    pub mft_modified_much_newer: bool,

    // -- Raw timestamps ---------------------------------------------------
    /// `$STANDARD_INFORMATION` creation time.
    pub si_created: NtfsTime,
    /// `$STANDARD_INFORMATION` modification time.
    pub si_modified: NtfsTime,
    /// `$STANDARD_INFORMATION` access time.
    pub si_accessed: NtfsTime,
    /// `$STANDARD_INFORMATION` MFT record modification time.
    pub si_mft_modified: NtfsTime,

    /// `$FILE_NAME` creation time.
    pub fn_created: NtfsTime,
    /// `$FILE_NAME` modification time.
    pub fn_modified: NtfsTime,
    /// `$FILE_NAME` access time.
    pub fn_accessed: NtfsTime,
    /// `$FILE_NAME` MFT record modification time.
    pub fn_mft_modified: NtfsTime,

    // -- Pairwise deltas --------------------------------------------------
    /// `si_created - fn_created` in 100-nanosecond intervals.
    /// Negative means `$SI` creation predates `$FN` creation.
    pub delta_created: i64,
    /// `si_modified - fn_modified` in 100-nanosecond intervals.
    pub delta_modified: i64,
    /// `si_accessed - fn_accessed` in 100-nanosecond intervals.
    pub delta_accessed: i64,
    /// `si_mft_modified - fn_mft_modified` in 100-nanosecond intervals.
    pub delta_mft_modified: i64,
}

impl NtfsTimestampAnomaly {
    /// Returns `true` if any heuristic triggered.
    pub fn has_anomalies(&self) -> bool {
        self.si_created_before_fn_created
            || self.si_modified_before_fn_created
            || self.si_second_precision
            || self.si_all_timestamps_identical
            || self.si_rounded_to_minute_or_hour
            || self.mft_modified_much_newer
    }

    /// Returns the number of triggered heuristics (0–6).
    ///
    /// Note: heuristics can overlap (e.g., minute-aligned timestamps
    /// are also second-aligned). This count reflects raw flag totals,
    /// not independent signals. Callers needing weighted scoring should
    /// inspect individual flags.
    pub fn anomaly_count(&self) -> u32 {
        u32::from(self.si_created_before_fn_created)
            + u32::from(self.si_modified_before_fn_created)
            + u32::from(self.si_second_precision)
            + u32::from(self.si_all_timestamps_identical)
            + u32::from(self.si_rounded_to_minute_or_hour)
            + u32::from(self.mft_modified_much_newer)
    }
}

/// Analyze `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps for
/// manipulation indicators using the default 30-day threshold for
/// `mft_modified_much_newer`.
///
/// This is pure computation — no filesystem I/O is required.
pub fn detect_timestamp_anomalies(
    si: &NtfsStandardInformation,
    fn_attr: &NtfsFileName,
) -> NtfsTimestampAnomaly {
    detect_timestamp_anomalies_with_threshold(si, fn_attr, DEFAULT_MFT_MODIFIED_THRESHOLD)
}

/// Analyze `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps for
/// manipulation indicators with a custom MFT-modification threshold.
///
/// `mft_threshold` is the minimum gap (in 100-nanosecond intervals)
/// between the MFT record modification time and the latest of
/// `$SI.created`/`$SI.modified` that triggers `mft_modified_much_newer`.
// mutants::skip: the `si_mft_modified > baseline` comparison guarding
// `mft_modified_much_newer` has a `>`->`>=` mutant that is provably
// equivalent: it differs only when `si_mft == baseline`, where the
// second clause `(si_mft - baseline) > mft_threshold` becomes
// `0 > mft_threshold`, always false for the `u64` threshold. No input can
// distinguish the two operators. (Every other behaviour of this function is
// covered by the `detect_*` unit tests below.)
#[cfg_attr(test, mutants::skip)]
pub fn detect_timestamp_anomalies_with_threshold(
    si: &NtfsStandardInformation,
    fn_attr: &NtfsFileName,
    mft_threshold: u64,
) -> NtfsTimestampAnomaly {
    let si_created = si.creation_time();
    let si_modified = si.modification_time();
    let si_accessed = si.access_time();
    let si_mft_modified = si.mft_record_modification_time();

    let fn_created = fn_attr.creation_time();
    let fn_modified = fn_attr.modification_time();
    let fn_accessed = fn_attr.access_time();
    let fn_mft_modified = fn_attr.mft_record_modification_time();

    let si_times = [
        si_created.nt_timestamp(),
        si_modified.nt_timestamp(),
        si_accessed.nt_timestamp(),
        si_mft_modified.nt_timestamp(),
    ];

    let delta_created = timestamp_delta(si_created, fn_created);
    let delta_modified = timestamp_delta(si_modified, fn_modified);
    let delta_accessed = timestamp_delta(si_accessed, fn_accessed);
    let delta_mft_modified = timestamp_delta(si_mft_modified, fn_mft_modified);

    let si_created_before_fn_created = si_created.nt_timestamp() < fn_created.nt_timestamp();

    let si_modified_before_fn_created = si_modified.nt_timestamp() < fn_created.nt_timestamp();

    let all_si_nonzero = si_times.iter().all(|t| *t != 0);

    // Only flag second-precision when timestamps are nonzero — zero
    // timestamps indicate uninitialized metadata, not timestomping.
    let si_second_precision =
        all_si_nonzero && si_times.iter().all(|t| t % INTERVALS_PER_SECOND == 0);

    let si_all_timestamps_identical = si_times[1..].iter().all(|t| *t == si_times[0]);

    // Minute-alignment subsumes hour-alignment (hour = 60 * minute),
    // so checking minute divisibility catches both cases. Skipped when
    // all timestamps are zero (uninitialized metadata, not timestomping).
    let si_rounded_to_minute_or_hour =
        all_si_nonzero && si_times.iter().all(|t| t % INTERVALS_PER_MINUTE == 0);

    let baseline = si_created.nt_timestamp().max(si_modified.nt_timestamp());
    let mft_modified_much_newer = si_mft_modified.nt_timestamp() > baseline
        && (si_mft_modified.nt_timestamp() - baseline) > mft_threshold;

    NtfsTimestampAnomaly {
        si_created_before_fn_created,
        si_modified_before_fn_created,
        si_second_precision,
        si_all_timestamps_identical,
        si_rounded_to_minute_or_hour,
        mft_modified_much_newer,
        si_created,
        si_modified,
        si_accessed,
        si_mft_modified,
        fn_created,
        fn_modified,
        fn_accessed,
        fn_mft_modified,
        delta_created,
        delta_modified,
        delta_accessed,
        delta_mft_modified,
    }
}

/// Compute signed delta between two timestamps in 100ns intervals.
/// Returns `a - b` as `i64`, saturating on overflow.
fn timestamp_delta(a: NtfsTime, b: NtfsTime) -> i64 {
    let a_val = a.nt_timestamp();
    let b_val = b.nt_timestamp();
    if a_val >= b_val {
        i64::try_from(a_val - b_val).unwrap_or(i64::MAX)
    } else {
        i64::try_from(b_val - a_val).map(|v| -v).unwrap_or(i64::MIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `NtfsStandardInformation` from four raw timestamps.
    ///
    /// Constructs a 48-byte resident attribute value (NTFS 1.x format)
    /// with the given timestamps and zeroed remaining fields.
    fn make_si(
        created: u64,
        modified: u64,
        mft_modified: u64,
        accessed: u64,
    ) -> NtfsStandardInformation {
        let mut buf = [0u8; 48];
        buf[0..8].copy_from_slice(&created.to_le_bytes());
        buf[8..16].copy_from_slice(&modified.to_le_bytes());
        buf[16..24].copy_from_slice(&mft_modified.to_le_bytes());
        buf[24..32].copy_from_slice(&accessed.to_le_bytes());
        NtfsStandardInformation::from_bytes_for_test(&buf)
    }

    /// Build an `NtfsFileName` from four raw timestamps.
    ///
    /// Constructs a minimal valid `$FILE_NAME` attribute with a
    /// single-character name ("X") and the given timestamps.
    fn make_fn(created: u64, modified: u64, mft_modified: u64, accessed: u64) -> NtfsFileName {
        // FileNameHeader: 66 bytes + 2 bytes for single UTF-16 char = 68
        let mut buf = [0u8; 68];
        // parent_directory_reference: 8 bytes at offset 0 (zeroed)
        // creation_time: offset 8
        buf[8..16].copy_from_slice(&created.to_le_bytes());
        // modification_time: offset 16
        buf[16..24].copy_from_slice(&modified.to_le_bytes());
        // mft_record_modification_time: offset 24
        buf[24..32].copy_from_slice(&mft_modified.to_le_bytes());
        // access_time: offset 32
        buf[32..40].copy_from_slice(&accessed.to_le_bytes());
        // allocated_size (8), data_size (8), file_attributes (4),
        // reparse_point_tag (4): offsets 40-63 (zeroed)
        // name_length: offset 64 — 1 character
        buf[64] = 1;
        // namespace: offset 65 — Win32AndDos (3)
        buf[65] = 3;
        // name: offset 66 — 'X' in UTF-16 LE
        buf[66] = b'X';
        buf[67] = 0;
        NtfsFileName::from_bytes_for_test(&buf)
    }

    // Base timestamp: a mid-range value with sub-second precision
    const BASE: u64 = 133_310_178_451_234_567;

    // One day in 100ns intervals
    const ONE_DAY: u64 = 24 * 3_600 * INTERVALS_PER_SECOND;

    #[test]
    fn clean_file_no_anomalies() {
        let si = make_si(BASE, BASE + ONE_DAY, BASE + ONE_DAY, BASE + ONE_DAY);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.has_anomalies());
        assert_eq!(result.anomaly_count(), 0);
    }

    #[test]
    fn si_created_before_fn_created() {
        let si = make_si(
            BASE - 10 * ONE_DAY,
            BASE + ONE_DAY,
            BASE + ONE_DAY,
            BASE + ONE_DAY,
        );
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_created_before_fn_created);
        assert!(!result.si_modified_before_fn_created);
        assert!(result.has_anomalies());
        assert!(result.delta_created < 0);
    }

    #[test]
    fn si_modified_before_fn_created() {
        let si = make_si(BASE, BASE - 5 * ONE_DAY, BASE + ONE_DAY, BASE + ONE_DAY);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.si_created_before_fn_created);
        assert!(result.si_modified_before_fn_created);
        assert!(result.has_anomalies());
    }

    #[test]
    fn si_second_precision_detected() {
        let second = INTERVALS_PER_SECOND;
        let t1 = 100 * second;
        let t2 = 200 * second;
        let t3 = 300 * second;
        let t4 = 400 * second;

        let si = make_si(t1, t2, t3, t4);
        let fn_attr = make_fn(t1, t1, t1, t1);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_second_precision);
        assert!(!result.si_all_timestamps_identical);
        assert!(result.has_anomalies());
    }

    #[test]
    fn si_second_precision_not_triggered_with_subsecond() {
        let si = make_si(BASE, BASE + 1, BASE + 2, BASE + 3);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.si_second_precision);
    }

    #[test]
    fn si_all_timestamps_identical_detected() {
        let si = make_si(BASE, BASE, BASE, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_all_timestamps_identical);
        assert!(result.has_anomalies());
    }

    #[test]
    fn si_rounded_to_minute() {
        let minute = INTERVALS_PER_MINUTE;
        let t = 1000 * minute;

        let si = make_si(t, t + minute, t + 2 * minute, t + 3 * minute);
        let fn_attr = make_fn(t, t, t, t);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_rounded_to_minute_or_hour);
        // Minute-aligned implies second-aligned
        assert!(result.si_second_precision);
    }

    #[test]
    fn si_rounded_to_hour() {
        // Hour = 60 minutes, so hour-aligned is also minute-aligned
        let hour = 60 * INTERVALS_PER_MINUTE;
        let t = 100 * hour;

        let si = make_si(t, t + hour, t + 2 * hour, t + 3 * hour);
        let fn_attr = make_fn(t, t, t, t);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_rounded_to_minute_or_hour);
    }

    #[test]
    fn rounded_not_triggered_with_subsecond() {
        let si = make_si(BASE, BASE + 1, BASE + 2, BASE + 3);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.si_rounded_to_minute_or_hour);
    }

    #[test]
    fn mft_modified_much_newer_detected() {
        // MFT modified 60 days after creation/modification
        let si = make_si(BASE, BASE + ONE_DAY, BASE + 60 * ONE_DAY, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.mft_modified_much_newer);
        assert!(result.has_anomalies());
    }

    #[test]
    fn mft_modified_within_threshold_no_trigger() {
        // MFT modified only 5 days after — within default 30-day threshold
        let si = make_si(BASE, BASE + ONE_DAY, BASE + 5 * ONE_DAY, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.mft_modified_much_newer);
    }

    #[test]
    fn mft_modified_exactly_at_threshold_no_trigger() {
        // Exactly at threshold boundary — strict > so should NOT trigger
        let baseline = BASE.max(BASE + ONE_DAY);
        let mft_time = baseline + DEFAULT_MFT_MODIFIED_THRESHOLD;
        let si = make_si(BASE, BASE + ONE_DAY, mft_time, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.mft_modified_much_newer);
    }

    #[test]
    fn mft_modified_one_tick_over_threshold() {
        let baseline = BASE.max(BASE + ONE_DAY);
        let mft_time = baseline + DEFAULT_MFT_MODIFIED_THRESHOLD + 1;
        let si = make_si(BASE, BASE + ONE_DAY, mft_time, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.mft_modified_much_newer);
    }

    #[test]
    fn mft_modified_before_baseline_no_trigger() {
        // MFT modified older than both created and modified
        let si = make_si(BASE + 60 * ONE_DAY, BASE + 60 * ONE_DAY, BASE, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.mft_modified_much_newer);
    }

    #[test]
    fn custom_threshold() {
        let seven_days = 7 * ONE_DAY;
        let si = make_si(BASE, BASE, BASE + 10 * ONE_DAY, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        // 10 days < 30-day default threshold
        let default_result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!default_result.mft_modified_much_newer);

        // 10 days > 7-day custom threshold
        let custom_result = detect_timestamp_anomalies_with_threshold(&si, &fn_attr, seven_days);
        assert!(custom_result.mft_modified_much_newer);
    }

    #[test]
    fn pairwise_deltas_correct() {
        let si = make_si(BASE + 100, BASE + 200, BASE + 300, BASE + 400);
        let fn_attr = make_fn(BASE, BASE + 500, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert_eq!(result.delta_created, 100);
        assert_eq!(result.delta_modified, -300);
        assert_eq!(result.delta_mft_modified, 300);
        assert_eq!(result.delta_accessed, 400);
    }

    #[test]
    fn negative_delta_no_overflow() {
        let si = make_si(1000, 1000, 1000, 1000);
        let fn_attr = make_fn(u64::MAX / 2, u64::MAX / 2, u64::MAX / 2, u64::MAX / 2);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.delta_created < 0);
        assert!(result.si_created_before_fn_created);
    }

    #[test]
    fn zero_timestamps_skip_precision_checks() {
        let si = make_si(0, 0, 0, 0);
        let fn_attr = make_fn(0, 0, 0, 0);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        // Zero timestamps are uninitialized — not flagged as precision anomalies
        assert!(!result.si_second_precision);
        assert!(!result.si_rounded_to_minute_or_hour);
        // But they are all identical
        assert!(result.si_all_timestamps_identical);
        // Equal, not less than
        assert!(!result.si_created_before_fn_created);
        assert!(!result.si_modified_before_fn_created);
        assert!(!result.mft_modified_much_newer);
    }

    #[test]
    fn si_second_precision_mixed_not_triggered() {
        // Three second-aligned, one with sub-second — should NOT trigger
        let second = INTERVALS_PER_SECOND;
        let si = make_si(100 * second, 200 * second, 300 * second, 300 * second + 1);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(!result.si_second_precision);
    }

    #[test]
    fn anomaly_count_classic_timestomping() {
        // Classic: all SI set to same second-precision value, backdated
        // stomped = 1000s, not minute-aligned (1000 % 60 != 0)
        let stomped = 100 * INTERVALS_PER_SECOND;
        let si = make_si(stomped, stomped, stomped, stomped);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_created_before_fn_created);
        assert!(result.si_modified_before_fn_created);
        assert!(result.si_second_precision);
        assert!(result.si_all_timestamps_identical);
        assert!(!result.si_rounded_to_minute_or_hour); // 100s not minute-aligned
        assert!(!result.mft_modified_much_newer); // mft == stomped <= baseline
        assert_eq!(result.anomaly_count(), 4);
    }

    #[test]
    fn anomaly_count_sums_all_contributing_flags() {
        // Construct a record where five distinct heuristics fire so each
        // `+` in `anomaly_count` is exercised with non-zero, non-identical
        // operands: si created/modified both precede fn_created and are
        // minute-aligned (=> second-precision + rounded), and the MFT
        // modification time is far past the baseline. The four SI
        // timestamps differ so `si_all_timestamps_identical` stays false.
        let minute = INTERVALS_PER_MINUTE;
        let fn_created = 1_000_000 * minute;
        let si_created = 100 * minute;
        let si_modified = 200 * minute;
        let si_accessed = 300 * minute;
        let baseline = si_created.max(si_modified);
        let si_mft = baseline + DEFAULT_MFT_MODIFIED_THRESHOLD + minute;

        let si = make_si(si_created, si_modified, si_mft, si_accessed);
        let fn_attr = make_fn(fn_created, fn_created, fn_created, fn_created);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert!(result.si_created_before_fn_created);
        assert!(result.si_modified_before_fn_created);
        assert!(result.si_second_precision);
        assert!(!result.si_all_timestamps_identical);
        assert!(result.si_rounded_to_minute_or_hour);
        assert!(result.mft_modified_much_newer);
        assert_eq!(result.anomaly_count(), 5);
    }

    #[test]
    fn anomaly_count_with_six_flags_when_identical_and_mft_newer_excluded() {
        // A second count value distinct from 5 to pin every `+` operator:
        // four identical second-precision SI timestamps that predate
        // fn_created. mft == the others, so `mft_modified_much_newer` is
        // false, but `si_all_timestamps_identical` is now true.
        let second = INTERVALS_PER_SECOND;
        let stomped = 100 * second; // not minute-aligned (100 % 60 != 0)
        let fn_created = 1_000_000 * second;

        let si = make_si(stomped, stomped, stomped, stomped);
        let fn_attr = make_fn(fn_created, fn_created, fn_created, fn_created);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        // created<fn, modified<fn, second_precision, all_identical = 4 flags.
        assert!(result.si_created_before_fn_created);
        assert!(result.si_modified_before_fn_created);
        assert!(result.si_second_precision);
        assert!(result.si_all_timestamps_identical);
        assert!(!result.si_rounded_to_minute_or_hour);
        assert!(!result.mft_modified_much_newer);
        assert_eq!(result.anomaly_count(), 4);
    }

    #[test]
    fn detect_with_threshold_boundary_strict_greater() {
        // Pin the `> threshold` comparison: a gap one tick over the
        // threshold triggers, exactly at the threshold does not.
        let one_tick_over = make_si(BASE, BASE, BASE + 100 + 1, BASE);
        let exactly_at = make_si(BASE, BASE, BASE + 100, BASE);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        assert!(
            detect_timestamp_anomalies_with_threshold(&one_tick_over, &fn_attr, 100)
                .mft_modified_much_newer
        );
        assert!(
            !detect_timestamp_anomalies_with_threshold(&exactly_at, &fn_attr, 100)
                .mft_modified_much_newer
        );
    }

    #[test]
    fn mixed_deltas_all_fields() {
        // Each field has a different sign: created +, modified -, accessed +, mft -
        let si = make_si(BASE + 1000, BASE - 2000, BASE + 3000, BASE - 4000);
        let fn_attr = make_fn(BASE, BASE, BASE, BASE);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert_eq!(result.delta_created, 1000);
        assert_eq!(result.delta_modified, -2000);
        assert_eq!(result.delta_mft_modified, 3000);
        assert_eq!(result.delta_accessed, -4000);
    }

    #[test]
    fn near_max_timestamps_no_panic() {
        // Large but non-saturating timestamps near u64::MAX / 4
        let big = u64::MAX / 4;
        let si = make_si(big, big + 1, big + 2, big + 3);
        let fn_attr = make_fn(big - 100, big + 200, big - 300, big + 400);

        let result = detect_timestamp_anomalies(&si, &fn_attr);
        assert_eq!(result.delta_created, 100);
        assert_eq!(result.delta_modified, -199);
        assert_eq!(result.delta_mft_modified, 302);
        assert_eq!(result.delta_accessed, -397);
    }

    #[test]
    fn timestamp_delta_saturation() {
        assert_eq!(
            timestamp_delta(NtfsTime::from(u64::MAX), NtfsTime::from(0)),
            i64::MAX
        );
        assert_eq!(
            timestamp_delta(NtfsTime::from(0), NtfsTime::from(u64::MAX)),
            i64::MIN
        );
    }
}
