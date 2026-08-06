use bitflags::bitflags;

use crate::error::{ExtError, Result};

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct CompatFeatures: u32 {
        const DIR_PREALLOC   = 0x0001;
        const IMAGIC_INODES  = 0x0002;
        const HAS_JOURNAL    = 0x0004;
        const EXT_ATTR       = 0x0008;
        const RESIZE_INODE   = 0x0010;
        const DIR_INDEX      = 0x0020;
        // Performance hint: lazy block-group initialization. Read-only
        // forensic parsing is unaffected — the kernel populates the
        // group on first write.
        const LAZY_BG        = 0x0040;
        // Exclude-bitmap location stored in `bg_exclude_bitmap_*`.
        // Used by snapshots; informational for a read-only parser.
        const EXCLUDE_BITMAP = 0x0100;
        const SPARSE_SUPER2  = 0x0200;
        const FAST_COMMIT    = 0x0400;
        const STABLE_INODES  = 0x0800;
        const ORPHAN_FILE    = 0x1000;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct IncompatFeatures: u32 {
        const COMPRESSION = 0x0001;
        const FILETYPE    = 0x0002;
        const RECOVER     = 0x0004;
        const JOURNAL_DEV = 0x0008;
        const META_BG     = 0x0010;
        const EXTENTS     = 0x0040;
        const _64BIT      = 0x0080;
        const MMP         = 0x0100;
        const FLEX_BG     = 0x0200;
        const EA_INODE    = 0x0400;
        const DIRDATA     = 0x1000;
        const CSUM_SEED   = 0x2000;
        const LARGEDIR    = 0x4000;
        const INLINE_DATA = 0x8000;
        const ENCRYPT     = 0x0001_0000;
        const CASEFOLD    = 0x0002_0000;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct RoCompatFeatures: u32 {
        const SPARSE_SUPER   = 0x0001;
        const LARGE_FILE     = 0x0002;
        const HUGE_FILE      = 0x0008;
        const GDT_CSUM       = 0x0010;
        const DIR_NLINK      = 0x0020;
        const EXTRA_ISIZE    = 0x0040;
        // Out-of-tree ext4 snapshot patch — surfaced with an explicit
        // error variant so callers can distinguish "unknown bit" from
        // "known-rejected snapshot filesystem".
        const HAS_SNAPSHOT   = 0x0080;
        const QUOTA          = 0x0100;
        const BIGALLOC       = 0x0200;
        const METADATA_CSUM  = 0x0400;
        const READONLY       = 0x1000;
        const PROJECT        = 0x2000;
        const VERITY         = 0x8000;
        const ORPHAN_PRESENT = 0x0001_0000;
    }
}

/// Incompat features safe to open for a read-only forensic parser.
const INCOMPAT_OPEN_ALLOWED: IncompatFeatures = IncompatFeatures::FILETYPE
    .union(IncompatFeatures::EXTENTS)
    .union(IncompatFeatures::_64BIT)
    .union(IncompatFeatures::MMP)
    .union(IncompatFeatures::FLEX_BG)
    .union(IncompatFeatures::EA_INODE)
    .union(IncompatFeatures::LARGEDIR)
    .union(IncompatFeatures::CASEFOLD)
    .union(IncompatFeatures::CSUM_SEED)
    .union(IncompatFeatures::META_BG);

/// Incompat features recognized but deferred to object-access time.
const INCOMPAT_OBJECT_LOCAL: IncompatFeatures =
    IncompatFeatures::INLINE_DATA.union(IncompatFeatures::ENCRYPT);

/// Incompat features recognized but rejected at open with specific errors.
const INCOMPAT_OPEN_REJECTED: IncompatFeatures = IncompatFeatures::RECOVER
    .union(IncompatFeatures::JOURNAL_DEV)
    .union(IncompatFeatures::COMPRESSION)
    .union(IncompatFeatures::DIRDATA);

const INCOMPAT_RECOGNIZED: IncompatFeatures = INCOMPAT_OPEN_ALLOWED
    .union(INCOMPAT_OBJECT_LOCAL)
    .union(INCOMPAT_OPEN_REJECTED);

/// Ro-compat features safe to open for a read-only forensic parser.
const RO_COMPAT_OPEN_ALLOWED: RoCompatFeatures = RoCompatFeatures::SPARSE_SUPER
    .union(RoCompatFeatures::LARGE_FILE)
    .union(RoCompatFeatures::HUGE_FILE)
    .union(RoCompatFeatures::GDT_CSUM)
    .union(RoCompatFeatures::DIR_NLINK)
    .union(RoCompatFeatures::EXTRA_ISIZE)
    .union(RoCompatFeatures::QUOTA)
    .union(RoCompatFeatures::BIGALLOC)
    .union(RoCompatFeatures::METADATA_CSUM)
    .union(RoCompatFeatures::READONLY)
    .union(RoCompatFeatures::PROJECT)
    .union(RoCompatFeatures::VERITY);

/// Ro-compat features recognized but rejected at open with specific errors.
///
/// `HAS_SNAPSHOT` is the out-of-tree ext4 snapshot patch (Lustre / older
/// e2fsprogs). The on-disk layout it implies (snapshot list + COW)
/// isn't modeled by this parser, so the open is rejected with a
/// dedicated error so callers can distinguish it from a generic
/// unknown-bit rejection.
const RO_COMPAT_OPEN_REJECTED: RoCompatFeatures =
    RoCompatFeatures::ORPHAN_PRESENT.union(RoCompatFeatures::HAS_SNAPSHOT);

const RO_COMPAT_RECOGNIZED: RoCompatFeatures =
    RO_COMPAT_OPEN_ALLOWED.union(RO_COMPAT_OPEN_REJECTED);

/// Parse-layer feature gating. Runs for both `open_lenient` and `new`.
/// Rejects features whose on-disk layout we cannot safely interpret.
///
/// `permit_journal_dev` is `true` only for the `open_with_external_journal`
/// entry point, which supplies the external journal device alongside the
/// filesystem reader. The single-reader `Ext::new` / `open_lenient` paths
/// pass `false` and keep rejecting `INCOMPAT_JOURNAL_DEV` with
/// `UnsupportedJournalDevice`.
pub(crate) fn validate_parse_features(
    incompat: IncompatFeatures,
    ro_compat: RoCompatFeatures,
    permit_journal_dev: bool,
) -> Result<()> {
    if !permit_journal_dev && incompat.contains(IncompatFeatures::JOURNAL_DEV) {
        return Err(ExtError::UnsupportedJournalDevice);
    }
    // Intentionally rejected: ext4 compression was never merged
    // upstream as a usable feature, and DIRDATA stores per-entry
    // payloads behind a kernel-internal hook (`fs/ext4/dir.c`). Neither
    // has a read-side decoder here.
    if incompat.contains(IncompatFeatures::COMPRESSION) {
        return Err(ExtError::UnsupportedCompression);
    }
    if incompat.contains(IncompatFeatures::DIRDATA) {
        return Err(ExtError::UnsupportedDirData);
    }
    // Out-of-tree snapshot patch — reject early so the diagnostic
    // points at the actual reason instead of "unknown bit".
    if ro_compat.contains(RoCompatFeatures::HAS_SNAPSHOT) {
        return Err(ExtError::UnsupportedSnapshotFeature);
    }

    let unknown_incompat = incompat.bits() & !INCOMPAT_RECOGNIZED.bits();
    if unknown_incompat != 0 {
        return Err(ExtError::UnsupportedIncompatFeature {
            flags: unknown_incompat,
        });
    }

    let unknown_ro = ro_compat.bits() & !RO_COMPAT_RECOGNIZED.bits();
    if unknown_ro != 0 {
        return Err(ExtError::UnsupportedRoCompatFeature { flags: unknown_ro });
    }

    Ok(())
}

/// Strict clean-state gating. Runs only for `Ext::new`.
/// Precedence: `NeedsRecovery` before `OrphanRecoveryRequired`.
pub(crate) fn validate_clean_state(
    incompat: IncompatFeatures,
    ro_compat: RoCompatFeatures,
) -> Result<()> {
    if incompat.contains(IncompatFeatures::RECOVER) {
        return Err(ExtError::NeedsRecovery);
    }
    if ro_compat.contains(RoCompatFeatures::ORPHAN_PRESENT) {
        return Err(ExtError::OrphanRecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_all(incompat: IncompatFeatures, ro_compat: RoCompatFeatures) -> Result<()> {
        validate_parse_features(incompat, ro_compat, false)?;
        validate_clean_state(incompat, ro_compat)
    }

    #[test]
    fn allows_modern_ext4_defaults() {
        let incompat = IncompatFeatures::FILETYPE
            | IncompatFeatures::EXTENTS
            | IncompatFeatures::_64BIT
            | IncompatFeatures::FLEX_BG
            | IncompatFeatures::CSUM_SEED;
        let ro_compat = RoCompatFeatures::SPARSE_SUPER
            | RoCompatFeatures::LARGE_FILE
            | RoCompatFeatures::HUGE_FILE
            | RoCompatFeatures::DIR_NLINK
            | RoCompatFeatures::EXTRA_ISIZE
            | RoCompatFeatures::METADATA_CSUM;
        assert!(validate_all(incompat, ro_compat).is_ok());
    }

    #[test]
    fn rejects_recover() {
        let incompat = IncompatFeatures::FILETYPE | IncompatFeatures::RECOVER;
        let ro_compat = RoCompatFeatures::empty();
        let err = validate_all(incompat, ro_compat).unwrap_err();
        assert!(
            matches!(err, ExtError::NeedsRecovery),
            "expected NeedsRecovery, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_incompat() {
        let incompat = IncompatFeatures::from_bits_retain(0x8000_0000);
        let ro_compat = RoCompatFeatures::empty();
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::UnsupportedIncompatFeature { flags: 0x8000_0000 }
            ),
            "expected UnsupportedIncompatFeature 0x80000000, got {err:?}"
        );
    }

    #[test]
    fn allows_object_local_incompat_at_open() {
        let incompat =
            IncompatFeatures::FILETYPE | IncompatFeatures::ENCRYPT | IncompatFeatures::INLINE_DATA;
        let ro_compat = RoCompatFeatures::empty();
        assert!(validate_all(incompat, ro_compat).is_ok());
    }

    #[test]
    fn rejects_orphan_present() {
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::ORPHAN_PRESENT;
        let err = validate_clean_state(incompat, ro_compat).unwrap_err();
        assert!(
            matches!(err, ExtError::OrphanRecoveryRequired),
            "expected OrphanRecoveryRequired, got {err:?}"
        );
    }

    #[test]
    fn journal_dev_permitted_when_external_journal_flag_set() {
        // `open_with_external_journal` passes `permit_journal_dev = true`;
        // the JOURNAL_DEV bit must then pass parse-feature gating.
        let incompat = IncompatFeatures::JOURNAL_DEV | IncompatFeatures::FILETYPE;
        assert!(
            validate_parse_features(incompat, RoCompatFeatures::empty(), true).is_ok(),
            "JOURNAL_DEV must be accepted when permit_journal_dev is set",
        );
        // Still rejected on the single-reader path.
        assert!(matches!(
            validate_parse_features(incompat, RoCompatFeatures::empty(), false),
            Err(ExtError::UnsupportedJournalDevice),
        ));
    }

    #[test]
    fn rejects_unknown_ro_compat() {
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::from_bits_retain(0x4000_0000);
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::UnsupportedRoCompatFeature { flags: 0x4000_0000 }
            ),
            "expected UnsupportedRoCompatFeature 0x40000000, got {err:?}"
        );
    }

    #[test]
    fn allows_bigalloc() {
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::BIGALLOC;
        assert!(validate_all(incompat, ro_compat).is_ok());
    }

    #[test]
    fn rejects_journal_device() {
        let incompat = IncompatFeatures::JOURNAL_DEV;
        let ro_compat = RoCompatFeatures::empty();
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(err, ExtError::UnsupportedJournalDevice),
            "expected UnsupportedJournalDevice, got {err:?}"
        );
    }

    #[test]
    fn parse_features_rejects_compression() {
        let incompat = IncompatFeatures::COMPRESSION;
        let ro_compat = RoCompatFeatures::empty();
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(err, ExtError::UnsupportedCompression),
            "expected UnsupportedCompression, got {err:?}"
        );
    }

    #[test]
    fn parse_features_rejects_dirdata() {
        let incompat = IncompatFeatures::DIRDATA;
        let ro_compat = RoCompatFeatures::empty();
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(err, ExtError::UnsupportedDirData),
            "expected UnsupportedDirData, got {err:?}"
        );
    }

    #[test]
    fn allows_mmp_and_casefold() {
        let incompat =
            IncompatFeatures::MMP | IncompatFeatures::CASEFOLD | IncompatFeatures::FILETYPE;
        let ro_compat = RoCompatFeatures::empty();
        assert!(validate_all(incompat, ro_compat).is_ok());
    }

    #[test]
    fn allows_quota_project_verity() {
        let incompat = IncompatFeatures::empty();
        let ro_compat =
            RoCompatFeatures::QUOTA | RoCompatFeatures::PROJECT | RoCompatFeatures::VERITY;
        assert!(validate_all(incompat, ro_compat).is_ok());
    }

    #[test]
    fn parse_features_accepts_dirty_state() {
        let incompat = IncompatFeatures::FILETYPE | IncompatFeatures::RECOVER;
        let ro_compat = RoCompatFeatures::ORPHAN_PRESENT;
        assert!(validate_parse_features(incompat, ro_compat, false).is_ok());
    }

    #[test]
    fn clean_state_rejects_recover_before_orphan() {
        let incompat = IncompatFeatures::RECOVER;
        let ro_compat = RoCompatFeatures::ORPHAN_PRESENT;
        let err = validate_clean_state(incompat, ro_compat).unwrap_err();
        assert!(matches!(err, ExtError::NeedsRecovery), "got {err:?}");
    }

    #[test]
    fn clean_state_rejects_orphan_when_recover_clear() {
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::ORPHAN_PRESENT;
        let err = validate_clean_state(incompat, ro_compat).unwrap_err();
        assert!(
            matches!(err, ExtError::OrphanRecoveryRequired),
            "got {err:?}"
        );
    }

    #[test]
    fn clean_state_accepts_clean_filesystem() {
        assert!(validate_clean_state(IncompatFeatures::empty(), RoCompatFeatures::empty()).is_ok());
    }

    #[test]
    fn parse_features_still_rejects_journal_dev() {
        let err = validate_parse_features(
            IncompatFeatures::JOURNAL_DEV,
            RoCompatFeatures::empty(),
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, ExtError::UnsupportedJournalDevice),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_features_accepts_meta_bg() {
        let incompat = IncompatFeatures::FILETYPE | IncompatFeatures::META_BG;
        let ro_compat = RoCompatFeatures::empty();
        assert!(
            validate_parse_features(incompat, ro_compat, false).is_ok(),
            "META_BG must be allowed at parse time"
        );
    }

    #[test]
    fn parse_features_rejects_has_snapshot_with_named_error() {
        // RO_COMPAT_HAS_SNAPSHOT = 0x0080. Previously opened as the
        // generic "unknown ro_compat" error; now distinguishable.
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::HAS_SNAPSHOT;
        let err = validate_parse_features(incompat, ro_compat, false).unwrap_err();
        assert!(
            matches!(err, ExtError::UnsupportedSnapshotFeature),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_features_accepts_lazy_bg_and_exclude_bitmap() {
        // Both are open-and-report compat bits: read-only parsing is
        // unaffected by lazy block-group init or snapshot exclude bitmaps.
        // Modelled as `CompatFeatures` so they're visible to callers,
        // not treated as unknown bits.
        let incompat = IncompatFeatures::empty();
        let ro_compat = RoCompatFeatures::empty();
        // Build raw u32 with LAZY_BG | EXCLUDE_BITMAP set on the compat
        // dword; round-trip through the bitflags layer.
        let compat_raw = 0x0040u32 | 0x0100u32;
        let compat = CompatFeatures::from_bits_retain(compat_raw);
        assert!(compat.contains(CompatFeatures::LAZY_BG));
        assert!(compat.contains(CompatFeatures::EXCLUDE_BITMAP));
        // validate_parse_features doesn't gate on compat, so this just
        // confirms the parser-layer policy is "accept and report".
        assert!(validate_parse_features(incompat, ro_compat, false).is_ok());
    }

    #[test]
    fn compression_and_dirdata_keep_named_rejection_intentionally() {
        // Documentation test: both features remain rejected by design
        // (no read-side decoder, on-disk layout dependent on kernel
        // hooks we don't model). Pin the named-error contract so a
        // future change can't quietly demote them to generic errors.
        let err = validate_parse_features(
            IncompatFeatures::COMPRESSION,
            RoCompatFeatures::empty(),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, ExtError::UnsupportedCompression));

        let err =
            validate_parse_features(IncompatFeatures::DIRDATA, RoCompatFeatures::empty(), false)
                .unwrap_err();
        assert!(matches!(err, ExtError::UnsupportedDirData));
    }
}
