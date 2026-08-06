//! Integration tests for ext4 orphan-file and legacy orphan-list recovery.

mod support;

use fs_ext::io::{Read as _, Seek as _, SeekFrom};
use fs_ext::{Ext, JournalReplay, OrphanReplay, OverlayReader};

fn fixture_available(name: &str) -> bool {
    fsmnt_testkit::fixture_path(env!("CARGO_MANIFEST_DIR"), format!("testdata/{name}")).exists()
}

#[test]
fn flag_only_orphan_fixture_recovers_and_strict_reopen_succeeds() {
    if !fixture_available("ext4-dirty-orphan.img") {
        eprintln!("skipping: ext4-dirty-orphan.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    assert!(pre.has_orphan_present());

    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");
    assert!(replay.orphan_plan().stop.is_none());
    assert!(replay.orphan_plan().legacy.is_empty());
    assert!(replay.orphan_plan().orphan_file.is_empty());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    let _ext = Ext::new(&mut overlay).expect("strict reopen");
}

#[test]
fn legacy_unlink_fixture_records_one_entry_and_succeeds() {
    if !fixture_available("ext4-dirty-legacy-unlink.img") {
        eprintln!("skipping: ext4-dirty-legacy-unlink.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-legacy-unlink.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");

    assert_eq!(replay.orphan_plan().legacy.len(), 1);
    assert!(matches!(
        replay.orphan_plan().legacy[0].disposition,
        fs_ext::OrphanDisposition::Unlinked,
    ));
    assert!(replay.orphan_plan().stop.is_none());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen");
}

#[test]
fn legacy_truncate_fixture_records_one_entry_and_succeeds() {
    if !fixture_available("ext4-dirty-legacy-truncate.img") {
        eprintln!("skipping: ext4-dirty-legacy-truncate.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-legacy-truncate.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");

    assert_eq!(replay.orphan_plan().legacy.len(), 1);
    assert!(matches!(
        replay.orphan_plan().legacy[0].disposition,
        fs_ext::OrphanDisposition::TruncateDeferred,
    ));
    assert!(replay.orphan_plan().stop.is_none());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen");
}

#[test]
fn legacy_cycle_fixture_halts_with_cycle_stop() {
    if !fixture_available("ext4-dirty-legacy-cycle.img") {
        eprintln!("skipping: ext4-dirty-legacy-cycle.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-legacy-cycle.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");

    let stop = replay.orphan_plan().stop.as_ref().expect("expected stop");
    assert!(matches!(
        stop.reason,
        fs_ext::OrphanStopReason::LegacyChainCycle { .. },
    ));
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
    // The cycle fixture does not set RO_COMPAT_ORPHAN_PRESENT, so strict
    // reopen succeeds — the stop surfaces only via orphan_plan().stop.
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen succeeds (no dirty bits set)");
}

#[test]
fn legacy_multi_fixture_records_three_unlinks_and_succeeds() {
    if !fixture_available("ext4-dirty-legacy-multi.img") {
        eprintln!("skipping: ext4-dirty-legacy-multi.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-legacy-multi.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");

    assert_eq!(replay.orphan_plan().legacy.len(), 3);
    for e in &replay.orphan_plan().legacy {
        assert!(matches!(e.disposition, fs_ext::OrphanDisposition::Unlinked));
    }
    assert!(replay.orphan_plan().stop.is_none());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen");
}

#[test]
fn truncate_fixtures_parse_via_open_lenient() {
    for name in [
        "ext4-dirty-orphan-truncate-unlink.img",
        "ext4-dirty-orphan-truncate-partial.img",
    ] {
        if !fixture_available(name) {
            eprintln!("skipping: {name} not generated");
            continue;
        }
        let mut fs = support::load_image(name);
        let _ext =
            Ext::open_lenient(&mut fs).unwrap_or_else(|err| panic!("open_lenient {name}: {err:?}"));
        // Smoke: image opens. Dirty-state assertions land in Task 16 / Task 29.
    }
}

#[test]
fn truncate_unlink_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-truncate-unlink.img") {
        eprintln!("skipping: ext4-dirty-orphan-truncate-unlink.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-truncate-unlink.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn truncate_partial_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-truncate-partial.img") {
        eprintln!("skipping: ext4-dirty-orphan-truncate-partial.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-truncate-partial.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn ea_cascade_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-ea-cascade.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-cascade.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-cascade.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn ea_multi_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-ea-multi.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-multi.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-multi.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn ea_partial_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-ea-partial.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-partial.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-partial.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn ea_missing_flag_fixture_halts_with_missing_flag_stop() {
    if !fixture_available("ext4-dirty-orphan-ea-missing-flag.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-missing-flag.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-missing-flag.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::EaInodeMissingFlag { .. }
        ),
        "expected EaInodeMissingFlag stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn ea_size_mismatch_fixture_halts_with_size_mismatch_stop() {
    if !fixture_available("ext4-dirty-orphan-ea-size-mismatch.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-size-mismatch.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-size-mismatch.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::EaInodeSizeMismatch { .. }
        ),
        "expected EaInodeSizeMismatch stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn ea_refcount_zero_fixture_halts_with_refcount_zero_stop() {
    if !fixture_available("ext4-dirty-orphan-ea-refcount-zero.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-refcount-zero.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-refcount-zero.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::EaInodeRefcountZero { .. }
        ),
        "expected EaInodeRefcountZero stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn ea_checksum_invalid_fixture_halts_with_checksum_invalid_stop() {
    if !fixture_available("ext4-dirty-orphan-ea-checksum-invalid.img") {
        eprintln!("skipping: ext4-dirty-orphan-ea-checksum-invalid.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-ea-checksum-invalid.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::EaInodeChecksumInvalid { .. }
        ),
        "expected EaInodeChecksumInvalid stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn shared_xattr_exclusive_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-shared-xattr-exclusive.img") {
        eprintln!("skipping: ext4-dirty-orphan-shared-xattr-exclusive.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-shared-xattr-exclusive.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn shared_xattr_shared_fixture_replays_cleanly() {
    if !fixture_available("ext4-dirty-orphan-shared-xattr-shared.img") {
        eprintln!("skipping: ext4-dirty-orphan-shared-xattr-shared.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-shared-xattr-shared.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "expected no stop, got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn shared_xattr_refcount_zero_fixture_halts_with_refcount_zero_stop() {
    if !fixture_available("ext4-dirty-orphan-shared-xattr-refcount-zero.img") {
        eprintln!("skipping: ext4-dirty-orphan-shared-xattr-refcount-zero.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-shared-xattr-refcount-zero.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::SharedXattrBlockRefcountZero { .. }
        ),
        "expected SharedXattrBlockRefcountZero stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn shared_xattr_refcount_overflow_fixture_halts_with_refcount_overflow_stop() {
    if !fixture_available("ext4-dirty-orphan-shared-xattr-refcount-overflow.img") {
        eprintln!("skipping: ext4-dirty-orphan-shared-xattr-refcount-overflow.img not generated");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-shared-xattr-refcount-overflow.img");
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::SharedXattrBlockRefcountOverflow { .. }
        ),
        "expected SharedXattrBlockRefcountOverflow stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

#[test]
fn orphan_file_fixture_recovers_when_present() {
    if !fixture_available("ext4-dirty-orphan-file.img") {
        eprintln!(
            "skipping: ext4-dirty-orphan-file.img not generated \
             (manual Linux VM fixture, see design spec §11)"
        );
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan-file.img");
    let pre = Ext::open_lenient(&mut fs).expect("lenient");
    assert!(pre.has_orphan_file());
    assert!(pre.has_orphan_present());

    let journal = JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan");

    if let Some(stop) = &replay.orphan_plan().stop {
        panic!("unexpected stop on manual orphan-file fixture: {stop:?}");
    }
    assert!(
        !replay.orphan_plan().orphan_file.is_empty(),
        "orphan-file fixture must contain at least one entry",
    );

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen");
}

#[test]
fn bigalloc_orphan_fixture_recovers_cleanly_when_present() {
    const NAME: &str = "ext4-dirty-orphan-bigalloc.img";
    if !fixture_available(NAME) {
        eprintln!(
            "skipping {NAME}: fixture not available (requires mkfs.ext4 -C 16384 on a Linux VM)"
        );
        return;
    }
    let mut fs = support::load_image(NAME);
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(
        replay.orphan_plan().stop.is_none(),
        "bigalloc fixture should not stop; got {:?}",
        replay.orphan_plan().stop,
    );
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict reopen on composed overlay");
}

#[test]
fn bigalloc_overlap_fixture_halts_with_overlap_stop_when_present() {
    const NAME: &str = "ext4-dirty-orphan-bigalloc-overlap.img";
    if !fixture_available(NAME) {
        eprintln!("skipping {NAME}: fixture not available (requires byte-patched bigalloc base)");
        return;
    }
    let mut fs = support::load_image(NAME);
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay.orphan_plan().stop.as_ref().expect("expected a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::BigallocClusterOverlap { .. }
        ),
        "expected BigallocClusterOverlap stop, got {:?}",
        stop.reason,
    );
    assert!(replay.delta_is_empty(), "stop-path delta must be empty");
}

// ---------------------------------------------------------------------------
// Overlay invariant tests (spec §7 invariants 4, 5, 8)
// ---------------------------------------------------------------------------

/// Invariant 4: `BigallocClusterOverlap` must not fire on non-bigalloc
/// filesystems. Iterates all deterministic non-bigalloc fixtures —
/// including those that produce other stop reasons — and asserts none
/// produce `BigallocClusterOverlap`.
#[test]
fn invariant_4_no_bigalloc_overlap_on_non_bigalloc_fixtures() {
    let fixtures = [
        "ext4-dirty-orphan-truncate-unlink.img",
        "ext4-dirty-orphan-truncate-partial.img",
        "ext4-dirty-orphan-ea-cascade.img",
        "ext4-dirty-orphan-ea-multi.img",
        "ext4-dirty-orphan-ea-partial.img",
        "ext4-dirty-orphan-ea-missing-flag.img",
        "ext4-dirty-orphan-ea-size-mismatch.img",
        "ext4-dirty-orphan-ea-refcount-zero.img",
        "ext4-dirty-orphan-ea-checksum-invalid.img",
        "ext4-dirty-orphan-shared-xattr-exclusive.img",
        "ext4-dirty-orphan-shared-xattr-shared.img",
        "ext4-dirty-orphan-shared-xattr-refcount-zero.img",
        "ext4-dirty-orphan-shared-xattr-refcount-overflow.img",
    ];
    for name in fixtures {
        if !fixture_available(name) {
            eprintln!("skipping invariant-4 check for {name}: fixture not available");
            continue;
        }
        let mut fs = support::load_image(name);
        let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
        let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
        let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
        if let Some(stop) = &replay.orphan_plan().stop {
            assert!(
                !matches!(
                    stop.reason,
                    fs_ext::OrphanStopReason::BigallocClusterOverlap { .. }
                ),
                "{name}: BigallocClusterOverlap must not fire on a non-bigalloc filesystem \
                 (got {:?})",
                stop.reason,
            );
        }
    }
}

/// Invariant 4 (positive): `BigallocClusterOverlap` fires end-to-end through
/// the full `OrphanReplay::build` pipeline when the VM fixture is present.
///
/// This test is skip-on-absence — the fixture requires a byte-patched bigalloc
/// image (see the bigalloc-overlap fixture generation instructions). When the
/// fixture is absent, this test skips cleanly with an explanatory message.
/// End-to-end bigalloc overlap coverage is therefore conditional on the VM
/// fixture; a synthetic pipeline driver that doesn't require real filesystem
/// images is a possible future addition.
#[test]
fn invariant_4_bigalloc_overlap_fires_end_to_end_on_overlap_scenario() {
    const NAME: &str = "ext4-dirty-orphan-bigalloc-overlap.img";
    if !fixture_available(NAME) {
        eprintln!(
            "skipping invariant-4 positive end-to-end check: {NAME} not available \
             (requires byte-patched bigalloc base image); end-to-end BigallocClusterOverlap \
             coverage is conditional on this VM fixture"
        );
        return;
    }
    let mut fs = support::load_image(NAME);
    let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
    let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    let stop = replay
        .orphan_plan()
        .stop
        .as_ref()
        .expect("bigalloc-overlap fixture must produce a stop");
    assert!(
        matches!(
            stop.reason,
            fs_ext::OrphanStopReason::BigallocClusterOverlap { .. }
        ),
        "expected BigallocClusterOverlap to flow end-to-end through OrphanReplay::build, \
         got {:?}",
        stop.reason,
    );
    assert!(
        replay.delta_is_empty(),
        "BigallocClusterOverlap stop must leave the delta empty"
    );
}

/// Invariant 5: after apply, the superblock's `s_free_blocks_count` equals
/// the sum of `bg_free_blocks_count` across all group descriptors.
///
/// `Ext::free_blocks()` computes from the GDT. The mutator's `finalize`
/// method applies the same delta to `s_free_blocks_count` in the sb-host
/// override. By re-opening through the composed overlay we read both
/// independently: the sb counter via raw bytes and the GDT sum via
/// `Ext::free_blocks()`. Any drift between them triggers a mismatch.
#[test]
fn invariant_5_sb_free_blocks_equals_sum_of_group_tallies_after_apply() {
    // All happy-path fixtures: those that end with stop.is_none() after apply.
    let happy_path = [
        "ext4-dirty-orphan-truncate-unlink.img",
        "ext4-dirty-orphan-truncate-partial.img",
        "ext4-dirty-orphan-ea-cascade.img",
        "ext4-dirty-orphan-ea-multi.img",
        "ext4-dirty-orphan-ea-partial.img",
        "ext4-dirty-orphan-shared-xattr-exclusive.img",
        "ext4-dirty-orphan-shared-xattr-shared.img",
    ];
    for name in happy_path {
        if !fixture_available(name) {
            eprintln!("skipping invariant-5 check for {name}: fixture not available");
            continue;
        }
        let mut fs = support::load_image(name);
        let pre = Ext::open_lenient(&mut fs).expect("open_lenient");
        let journal = JournalReplay::build(&pre, &mut fs).expect("journal build");
        let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
        assert!(
            replay.orphan_plan().stop.is_none(),
            "{name}: expected no stop for happy-path fixture, got {:?}",
            replay.orphan_plan().stop,
        );

        // Re-open via the composed overlay to read updated GDT.
        let mut overlay = OverlayReader::new(&mut fs, &replay);
        let post = Ext::new(&mut overlay).expect("strict reopen");
        let gdt_sum = post.free_blocks();

        // Read s_free_blocks_count_{lo,hi} directly from the overlay bytes.
        // Superblock is at byte offset 1024; s_free_blocks_count_lo at +0x0C,
        // s_free_blocks_count_hi (64-bit only) at superblock +0x150.
        let mut overlay2 = OverlayReader::new(&mut fs, &replay);

        let mut buf4 = [0u8; 4];
        overlay2
            .seek(SeekFrom::Start(1024 + 0x0C))
            .expect("seek to s_free_blocks_count_lo");
        overlay2
            .read_exact(&mut buf4)
            .expect("read s_free_blocks_count_lo");
        let sb_lo = u32::from_le_bytes(buf4);

        let sb_hi = if post.is_64bit() {
            overlay2
                .seek(SeekFrom::Start(1024 + 0x150))
                .expect("seek to s_free_blocks_count_hi");
            overlay2
                .read_exact(&mut buf4)
                .expect("read s_free_blocks_count_hi");
            u32::from_le_bytes(buf4)
        } else {
            0u32
        };

        let sb_free_blocks = (u64::from(sb_hi) << 32) | u64::from(sb_lo);
        assert_eq!(
            sb_free_blocks, gdt_sum,
            "{name}: sb s_free_blocks_count ({sb_free_blocks}) != sum of group bg_free_blocks_count \
             ({gdt_sum}) after apply",
        );
    }
}

// Invariant 8 (surviving extents satisfy ee_block + ee_len <= cutoff * blocks_per_cluster)
// is covered at the unit level by
// `complete_truncate_partial_retains_first_cluster_and_frees_rest` in
// crates/fs-ext/src/orphan/truncate.rs (Task 16). No separate integration
// test is added here to avoid duplication.
