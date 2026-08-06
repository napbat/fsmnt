use super::*;

#[test]
fn test_mft_record_parse_failed_display_includes_record_and_cause() {
    let inner = NtfsError::InvalidFileSignature {
        position: NtfsPosition::none(),
        expected: b"FILE",
        actual: [0x00, 0x00, 0x00, 0x00],
    };
    let outer = NtfsError::MftRecordParseFailed {
        record_number: 42,
        source: Box::new(inner),
    };
    let msg = outer.to_string();
    assert!(
        msg.contains("42"),
        "Display should include record number: {msg}",
    );
    assert!(
        msg.contains("signature"),
        "Display should include inner cause: {msg}",
    );
}

#[test]
fn test_mft_record_parse_failed_source_chain() {
    use std::error::Error;

    let inner = NtfsError::InvalidFileSignature {
        position: NtfsPosition::none(),
        expected: b"FILE",
        actual: [0xDE, 0xAD, 0xBE, 0xEF],
    };
    let outer = NtfsError::MftRecordParseFailed {
        record_number: 99,
        source: Box::new(inner),
    };
    let source = outer.source().expect("should have source");
    let source_msg = source.to_string();
    assert!(
        source_msg.contains("signature"),
        "source should be the inner error: {source_msg}",
    );
}

#[test]
fn test_mft_record_parse_failed_pattern_match() {
    let inner = NtfsError::UpdateSequenceNumberMismatch {
        position: NtfsPosition::none(),
        expected: [0x01, 0x00],
        actual: [0xFF, 0xFF],
    };
    let error = NtfsError::MftRecordParseFailed {
        record_number: 1234,
        source: Box::new(inner),
    };
    match &error {
        NtfsError::MftRecordParseFailed {
            record_number,
            source,
        } => {
            assert_eq!(*record_number, 1234);
            assert!(matches!(
                **source,
                NtfsError::UpdateSequenceNumberMismatch { .. }
            ),);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn fs_error_io_kind_maps_correctly() {
    let err = NtfsError::Io(io::ErrorKind::UnexpectedEof.into());
    assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::UnexpectedEof),);
}

#[test]
fn fs_error_non_io_has_no_io_kind() {
    let err = NtfsError::InvalidTime;
    assert_eq!(FsError::io_kind(&err), None);
}

#[test]
fn into_io_error_unwraps_io_variant() {
    // The `NtfsError::Io(e) => e` arm must return the wrapped error
    // unchanged, preserving its original kind. Deleting the arm would
    // re-wrap it via `io::Error::other`, downgrading the kind to `Other`.
    let original = NtfsError::Io(io::ErrorKind::InvalidInput.into());
    let converted: io::Error = original.into();
    assert_eq!(converted.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn into_io_error_wraps_non_io_variant() {
    // A non-Io error has no inherent io kind, so the conversion wraps it.
    let converted: io::Error = NtfsError::InvalidTime.into();
    assert_eq!(converted.kind(), io::ErrorKind::Other);
}

#[test]
fn fs_error_byte_offset_from_position() {
    let err = NtfsError::InvalidFileSignature {
        position: NtfsPosition::new(0x1000),
        expected: b"FILE",
        actual: [0; 4],
    };
    assert_eq!(FsError::byte_offset(&err), Some(0x1000));
}

#[test]
fn fs_error_byte_offset_none_position() {
    let err = NtfsError::InvalidFileSignature {
        position: NtfsPosition::none(),
        expected: b"FILE",
        actual: [0; 4],
    };
    // NtfsPosition::none() wraps None, so byte_offset is None
    assert_eq!(FsError::byte_offset(&err), None);
}

#[test]
fn fs_error_byte_offset_no_position_variant() {
    let err = NtfsError::InvalidTime;
    assert_eq!(FsError::byte_offset(&err), None);
}

#[test]
fn from_fs_common_io_error() {
    let io_err = fse::IoError::new(fse::ErrorKind::Interrupted);
    let ntfs_err: NtfsError = io_err.into();
    match ntfs_err {
        NtfsError::Io(e) => {
            assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        }
        _ => panic!("Expected NtfsError::Io"),
    }
}

#[test]
fn test_bitlocker_encrypted_display() {
    let err = NtfsError::BitLockerEncrypted {
        position: NtfsPosition::new(0x03),
        oem_id: *b"-FVE-FS-",
    };
    let msg = err.to_string();
    assert!(msg.contains("BitLocker"), "should mention BitLocker: {msg}");
    assert!(msg.contains("0x3"), "should include position: {msg}");
    assert!(msg.contains("Decrypt"), "should suggest decryption: {msg}");
}

#[test]
fn test_bitlocker_encrypted_byte_offset() {
    let err = NtfsError::BitLockerEncrypted {
        position: NtfsPosition::new(0x03),
        oem_id: *b"-FVE-FS-",
    };
    assert_eq!(FsError::byte_offset(&err), Some(3));
}
