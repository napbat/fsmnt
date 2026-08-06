//! MFT Mirror ($`MFTMirr`) consistency validation.
//!
//! `$MFTMirr` is a backup copy of the first 4 MFT file records
//! (records 0-3: `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`).
//! Comparing these records byte-for-byte (after fixup) detects
//! corruption or tampering — for example, an attacker modifying
//! MFT entries without updating the mirror.

use alloc::vec;

use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::record::Record;
use crate::types::NtfsPosition;

/// Number of MFT records mirrored by `$MFTMirr`.
const MIRRORED_RECORD_COUNT: usize = 4;

/// Expected FILE record signature.
const FILE_SIGNATURE: &[u8; 4] = b"FILE";

/// Per-record comparison result between `$MFT` and `$MFTMirr`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NtfsMftMirrRecordStatus {
    /// The record bytes match exactly after fixup.
    Match,
    /// The records differ. `first_difference_offset` is the byte
    /// offset within the record where the first difference occurs.
    Mismatch {
        /// Byte offset of the first differing byte within the record.
        first_difference_offset: usize,
    },
    /// The primary MFT record could not be read (I/O or parse error).
    MftReadError {
        /// Static diagnostic describing the primary-record failure.
        message: &'static str,
    },
    /// The mirror record could not be read from disk.
    MirrorReadError {
        /// Static diagnostic describing the mirror read failure.
        message: &'static str,
    },
    /// The mirror record does not have a valid `FILE` signature.
    MirrorInvalidSignature {
        /// Four signature bytes observed in the mirror record.
        actual: [u8; 4],
    },
    /// The mirror record's Update Sequence Array fixup failed,
    /// indicating sector-level corruption.
    MirrorFixupFailed,
}

impl NtfsMftMirrRecordStatus {
    /// Returns `true` if this record is a byte-for-byte match.
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

/// Result of comparing `$MFT` records 0-3 against `$MFTMirr`.
#[derive(Clone, Debug)]
pub struct NtfsMftMirrValidation {
    records: [NtfsMftMirrRecordStatus; MIRRORED_RECORD_COUNT],
    mft_mirror_position: NtfsPosition,
}

impl NtfsMftMirrValidation {
    /// Returns the per-record status for records 0 (`$MFT`),
    /// 1 (`$MFTMirr`), 2 (`$LogFile`), and 3 (`$Volume`).
    #[must_use]
    pub fn records(&self) -> &[NtfsMftMirrRecordStatus; MIRRORED_RECORD_COUNT] {
        &self.records
    }

    /// Returns the absolute byte position of `$MFTMirr` on disk.
    #[must_use]
    pub fn mft_mirror_position(&self) -> NtfsPosition {
        self.mft_mirror_position
    }

    /// Returns `true` if all 4 mirrored records match.
    pub fn is_consistent(&self) -> bool {
        self.records.iter().all(NtfsMftMirrRecordStatus::is_match)
    }

    /// Returns the number of records that are NOT a match.
    #[must_use]
    pub fn anomaly_count(&self) -> usize {
        self.records.iter().filter(|r| !r.is_match()).count()
    }
}

/// Reads a raw MFT record from an absolute byte position and applies fixup.
///
/// Returns the post-fixup record data, or an error describing what went wrong.
fn read_raw_record<T>(
    fs: &mut T,
    position: NtfsPosition,
    record_size: u32,
) -> core::result::Result<Record, NtfsMftMirrRecordStatus>
where
    T: Read + Seek,
{
    let pos_value = position
        .value()
        .ok_or(NtfsMftMirrRecordStatus::MirrorReadError {
            message: "mirror position is None",
        })?;

    fs.seek(SeekFrom::Start(pos_value.get())).map_err(|_| {
        NtfsMftMirrRecordStatus::MirrorReadError {
            message: "seek failed",
        }
    })?;

    let record_size =
        usize::try_from(record_size).map_err(|_| NtfsMftMirrRecordStatus::MirrorReadError {
            message: "record size does not fit the address space",
        })?;
    let mut data = vec![0u8; record_size];
    fs.read_exact(&mut data)
        .map_err(|_| NtfsMftMirrRecordStatus::MirrorReadError {
            message: "read failed",
        })?;

    let mut record = Record::new(data, position);

    // Validate FILE signature.
    let signature = record
        .signature()
        .map_err(|_| NtfsMftMirrRecordStatus::MirrorReadError {
            message: "record too small for header",
        })?;
    if &signature != FILE_SIGNATURE {
        return Err(NtfsMftMirrRecordStatus::MirrorInvalidSignature { actual: signature });
    }

    // Apply fixup.
    record
        .fixup()
        .map_err(|_| NtfsMftMirrRecordStatus::MirrorFixupFailed)?;

    Ok(record)
}

/// Compares records 0-3 from `$MFT` and `$MFTMirr` byte-for-byte.
///
/// Reads the first 4 records from the MFT Mirror location (stored in
/// the boot sector) and compares each against the corresponding
/// record from the primary MFT. Returns per-record match/mismatch
/// status.
///
/// This function always succeeds if basic I/O works — individual
/// record failures (bad signature, fixup errors) are captured in
/// the per-record status rather than returned as errors.
///
/// # Errors
///
/// Returns an error if an MFT or mirror record is malformed or cannot be read.
pub fn validate_mft_mirror<T>(ntfs: &Ntfs, fs: &mut T) -> Result<NtfsMftMirrValidation>
where
    T: Read + Seek,
{
    let record_size = ntfs.file_record_size();
    let mirror_base = ntfs.mft_mirror_position();

    let mut records = [
        NtfsMftMirrRecordStatus::Match,
        NtfsMftMirrRecordStatus::Match,
        NtfsMftMirrRecordStatus::Match,
        NtfsMftMirrRecordStatus::Match,
    ];

    for (i, (record_number, status)) in [0_u64, 1, 2, 3]
        .into_iter()
        .zip(records.iter_mut())
        .enumerate()
    {
        // Read from primary MFT via the standard path.
        let Ok(mft_file) = ntfs.file(fs, record_number) else {
            *status = NtfsMftMirrRecordStatus::MftReadError {
                message: MFT_READ_ERROR_MESSAGES[i],
            };
            continue;
        };

        // Read the corresponding record from the mirror using checked
        // arithmetic to prevent wrapping on a crafted mirror base.
        let mirror_offset = record_number.checked_mul(u64::from(record_size)).ok_or(
            NtfsError::InvalidFileRecordNumber {
                file_record_number: record_number,
            },
        )?;

        let mirror_base_value = if let Some(v) = mirror_base.value() {
            v.get()
        } else {
            *status = NtfsMftMirrRecordStatus::MirrorReadError {
                message: "mirror base position is None",
            };
            continue;
        };
        let Some(mirror_abs) = mirror_base_value.checked_add(mirror_offset) else {
            *status = NtfsMftMirrRecordStatus::MirrorReadError {
                message: "mirror position overflow",
            };
            continue;
        };
        let mirror_pos = NtfsPosition::new(mirror_abs);
        let mirror_record = match read_raw_record(fs, mirror_pos, record_size) {
            Ok(r) => r,
            Err(s) => {
                *status = s;
                continue;
            }
        };

        // Compare post-fixup bytes.
        let mft_data = mft_file.record_data();
        let mirr_data = mirror_record.data();
        let cmp_len = mft_data.len().min(mirr_data.len());

        let first_diff = mft_data[..cmp_len]
            .iter()
            .zip(mirr_data[..cmp_len].iter())
            .position(|(a, b)| a != b);

        if let Some(offset) = first_diff {
            *status = NtfsMftMirrRecordStatus::Mismatch {
                first_difference_offset: offset,
            };
        } else if mft_data.len() != mirr_data.len() {
            *status = NtfsMftMirrRecordStatus::Mismatch {
                first_difference_offset: cmp_len,
            };
        }
        // Otherwise stays Match.
    }

    Ok(NtfsMftMirrValidation {
        records,
        mft_mirror_position: mirror_base,
    })
}

/// Error messages for failed MFT record reads, indexed by record number.
const MFT_READ_ERROR_MESSAGES: [&str; MIRRORED_RECORD_COUNT] = [
    "failed to read $MFT record 0",
    "failed to read $MFTMirr record 1",
    "failed to read $LogFile record 2",
    "failed to read $Volume record 3",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::synthetic;

    /// Places a record at byte offset 512 in a buffer, returning a cursor and
    /// the (non-zero) position to read it from.
    fn record_at_offset(record: &[u8; synthetic::RECORD_SIZE]) -> std::io::Cursor<Vec<u8>> {
        let mut buf = vec![0u8; 512 + synthetic::RECORD_SIZE];
        buf[512..512 + synthetic::RECORD_SIZE].copy_from_slice(record);
        std::io::Cursor::new(buf)
    }

    #[test]
    fn test_read_raw_record_valid_signature() {
        // A synthetic FILE record with valid signature and fixup must be
        // accepted by read_raw_record (guards `&signature != FILE_SIGNATURE`).
        let record = synthetic::file_record(0x0001, 1, 1, &[]);
        let mut cursor = record_at_offset(&record);
        let pos = NtfsPosition::new(512);
        let parsed = read_raw_record(
            &mut cursor,
            pos,
            u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32"),
        )
        .expect("valid FILE record must parse");
        assert_eq!(&parsed.data()[0..4], b"FILE");
    }

    #[test]
    fn test_read_raw_record_invalid_signature() {
        // A record whose signature is not "FILE" must yield
        // MirrorInvalidSignature with the actual bytes.
        let mut record = synthetic::file_record(0x0001, 1, 1, &[]);
        record[0..4].copy_from_slice(b"BAAD");
        let mut cursor = record_at_offset(&record);
        let pos = NtfsPosition::new(512);
        let err = read_raw_record(
            &mut cursor,
            pos,
            u32::try_from(synthetic::RECORD_SIZE).expect("test value fits u32"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            NtfsMftMirrRecordStatus::MirrorInvalidSignature { actual } if &actual == b"BAAD"
        ));
    }

    /// Builds an image with a working $MFT (records 0-3) plus a $`MFTMirr`
    /// region at LCN 4 holding byte-identical copies of records 0-3.
    fn synthetic_mirror_image() -> std::io::Cursor<Vec<u8>> {
        // Records 1-3 are simple in-use FILE records; record 0 is generated
        // as $MFT by mft_image. We need the mirror to hold the SAME pre-fixup
        // bytes as the primary, so we replicate them.
        let r1 = synthetic::file_record(0x0001, 1, 1, &[]);
        let r2 = synthetic::file_record(0x0001, 1, 1, &[]);
        let r3 = synthetic::file_record(0x0001, 1, 1, &[]);
        let mut image = synthetic::mft_image(&[r1, r2, r3]);

        // Copy primary records 0-3 into the mirror region (LCN 64).
        let mft_byte = 2 * synthetic::SECTOR_SIZE;
        let mirror_byte = 64 * synthetic::SECTOR_SIZE;
        for i in 0..4 {
            let src = mft_byte + i * synthetic::RECORD_SIZE;
            let dst = mirror_byte + i * synthetic::RECORD_SIZE;
            let (a, b) = image.split_at_mut(dst);
            b[..synthetic::RECORD_SIZE].copy_from_slice(&a[src..src + synthetic::RECORD_SIZE]);
        }
        std::io::Cursor::new(image)
    }

    #[test]
    fn test_synthetic_validate_mft_mirror_consistent() {
        let mut cursor = synthetic_mirror_image();
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = validate_mft_mirror(&ntfs, &mut cursor).unwrap();

        // All four records have identical primary/mirror bytes, so each
        // comparison's `a != b` finds no difference and lengths are equal.
        assert!(result.is_consistent());
        assert_eq!(result.anomaly_count(), 0);
        for r in result.records() {
            assert!(r.is_match());
        }
    }

    #[test]
    fn test_synthetic_validate_mft_mirror_detects_byte_mismatch() {
        let mut cursor = synthetic_mirror_image();
        let mut image = cursor.into_inner();

        // Corrupt one byte of mirror record 1, past the fixup area, so the
        // byte-for-byte comparison (`a != b`, line 207) reports a mismatch.
        let mirror_byte = 64 * synthetic::SECTOR_SIZE;
        let corrupt = mirror_byte + synthetic::RECORD_SIZE + 100;
        image[corrupt] ^= 0xFF;

        cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = validate_mft_mirror(&ntfs, &mut cursor).unwrap();

        assert!(!result.is_consistent());
        assert!(matches!(
            result.records()[1],
            NtfsMftMirrRecordStatus::Mismatch { .. }
        ));
        // Records 0, 2, 3 still match.
        assert!(result.records()[0].is_match());
        assert!(result.records()[2].is_match());
        assert!(result.records()[3].is_match());
    }

    #[test]
    fn test_validate_mft_mirror_consistent() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let result = validate_mft_mirror(&ntfs, &mut testfs1).unwrap();

        // A freshly-created filesystem should have a consistent mirror.
        assert!(
            result.is_consistent(),
            "expected all 4 records to match, got: {result:?}"
        );
        assert_eq!(result.anomaly_count(), 0);
    }

    #[test]
    fn test_mft_mirror_position_nonzero() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pos = ntfs.mft_mirror_position();
        assert!(pos.value().is_some(), "mirror position should be nonzero");
    }

    #[test]
    fn test_convenience_method() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let result = ntfs.mft_mirr_validation(&mut testfs1).unwrap();
        assert!(result.is_consistent());
    }

    #[test]
    fn test_record_status_is_match() {
        assert!(NtfsMftMirrRecordStatus::Match.is_match());
        assert!(
            !NtfsMftMirrRecordStatus::Mismatch {
                first_difference_offset: 0
            }
            .is_match()
        );
        assert!(!NtfsMftMirrRecordStatus::MirrorFixupFailed.is_match());
        assert!(!NtfsMftMirrRecordStatus::MirrorInvalidSignature { actual: *b"BAAD" }.is_match());
        assert!(!NtfsMftMirrRecordStatus::MftReadError { message: "test" }.is_match());
        assert!(!NtfsMftMirrRecordStatus::MirrorReadError { message: "test" }.is_match());
    }

    #[test]
    fn test_anomaly_count() {
        let validation = NtfsMftMirrValidation {
            records: [
                NtfsMftMirrRecordStatus::Match,
                NtfsMftMirrRecordStatus::Mismatch {
                    first_difference_offset: 42,
                },
                NtfsMftMirrRecordStatus::Match,
                NtfsMftMirrRecordStatus::MirrorFixupFailed,
            ],
            mft_mirror_position: NtfsPosition::new(1024),
        };

        assert!(!validation.is_consistent());
        assert_eq!(validation.anomaly_count(), 2);
    }

    #[test]
    fn test_all_match_anomaly_count_zero() {
        let validation = NtfsMftMirrValidation {
            records: [
                NtfsMftMirrRecordStatus::Match,
                NtfsMftMirrRecordStatus::Match,
                NtfsMftMirrRecordStatus::Match,
                NtfsMftMirrRecordStatus::Match,
            ],
            mft_mirror_position: NtfsPosition::new(1024),
        };

        assert!(validation.is_consistent());
        assert_eq!(validation.anomaly_count(), 0);
    }

    #[test]
    fn test_mft_mirror_records_match_primary_mft() {
        // Verify that each mirror record has identical bytes to the
        // primary MFT record for records 0-3.
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let record_size = ntfs.file_record_size();

        for i in 0..MIRRORED_RECORD_COUNT {
            let record_number = u64::try_from(i).expect("test record number fits in u64");
            let mft_file = ntfs.file(&mut testfs1, record_number).unwrap();
            let mft_data = mft_file.record_data();

            let mirror_pos = ntfs.mft_mirror_position() + (record_number * u64::from(record_size));
            let mirror_record = read_raw_record(&mut testfs1, mirror_pos, record_size)
                .unwrap_or_else(|e| {
                    panic!("mirror record {i} read failed: {e:?}");
                });

            assert_eq!(
                mft_data,
                mirror_record.data(),
                "record {i} bytes differ between MFT and MFTMirr"
            );
        }
    }

    #[test]
    fn test_corrupted_mirror_detects_mismatch() {
        // Copy testfs1 into a mutable buffer, corrupt one mirror record
        // byte, and verify validate_mft_mirror reports a mismatch.
        let Some(testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut data = testfs1.into_inner();

        // Parse the intact filesystem first to learn positions.
        let mut cursor = std::io::Cursor::new(&data[..]);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let mirror_pos = usize::try_from(ntfs.mft_mirror_position().value().unwrap().get())
            .expect("test value fits usize");

        // Corrupt byte 40 of mirror record 0 (inside the record header,
        // past the fixup area, so fixup still succeeds but content differs).
        let corrupt_offset = mirror_pos + 40;
        data[corrupt_offset] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(&data[..]);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = validate_mft_mirror(&ntfs, &mut cursor).unwrap();

        assert!(!result.is_consistent());
        assert!(result.anomaly_count() >= 1);

        // Record 0 should be a mismatch.
        assert!(
            matches!(
                result.records()[0],
                NtfsMftMirrRecordStatus::Mismatch { .. }
            ),
            "expected mismatch for record 0, got: {:?}",
            result.records()[0]
        );

        // The remaining records should still match.
        for i in 1..4 {
            assert!(
                result.records()[i].is_match(),
                "record {i} should still match, got: {:?}",
                result.records()[i]
            );
        }
    }

    #[test]
    fn test_corrupted_mirror_invalid_signature() {
        // Overwrite the FILE signature of mirror record 2 to detect
        // MirrorInvalidSignature status.
        let Some(testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut data = testfs1.into_inner();

        let mut cursor = std::io::Cursor::new(&data[..]);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let mirror_pos = usize::try_from(ntfs.mft_mirror_position().value().unwrap().get())
            .expect("test value fits usize");
        let record_size =
            usize::try_from(ntfs.file_record_size()).expect("test record size fits in usize");

        // Corrupt the signature of mirror record 2 ($LogFile).
        let sig_offset = mirror_pos + 2 * record_size;
        data[sig_offset..sig_offset + 4].copy_from_slice(b"BAAD");

        let mut cursor = std::io::Cursor::new(&data[..]);
        let ntfs = Ntfs::new(&mut cursor).unwrap();
        let result = validate_mft_mirror(&ntfs, &mut cursor).unwrap();

        assert!(!result.is_consistent());
        assert!(
            matches!(
                result.records()[2],
                NtfsMftMirrRecordStatus::MirrorInvalidSignature { actual }
                    if &actual == b"BAAD"
            ),
            "expected MirrorInvalidSignature for record 2, got: {:?}",
            result.records()[2]
        );

        // Other records should still be fine.
        assert!(result.records()[0].is_match());
        assert!(result.records()[1].is_match());
        assert!(result.records()[3].is_match());
    }

    #[test]
    fn test_mirror_position_matches_boot_sector() {
        use crate::boot_sector::{BootSector, BootSectorExt};
        use fs_common::boot_sector::BOOT_SECTOR_SIZE;
        use zerocopy::FromBytes;

        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // Re-read boot sector to get the raw LCN.
        testfs1.rewind().unwrap();
        let mut bs_bytes = [0u8; BOOT_SECTOR_SIZE];
        testfs1.read_exact(&mut bs_bytes).unwrap();
        let bs = BootSector::ref_from_bytes(&bs_bytes).unwrap();
        let lcn = bs.mft_mirr_lcn().unwrap();
        let expected_pos = lcn.position(&ntfs).unwrap();

        assert_eq!(ntfs.mft_mirror_position(), expected_pos);
    }
}
