pub type Result<T, E = BitLockerError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BitLockerError {
    #[error("Invalid FVE metadata in block {block_index}: {reason}")]
    InvalidMetadata {
        block_index: u8,
        reason: MetadataFailure,
    },

    #[error("All three FVE metadata blocks are corrupt: [0] {}, [1] {}, [2] {}", failures[0], failures[1], failures[2])]
    AllMetadataBlocksCorrupt { failures: [MetadataFailure; 3] },

    #[error("Unsupported BitLocker version: {version}")]
    UnsupportedVersion { version: u16 },

    #[error("Unsupported FVE datum type: {datum_type:#06x}")]
    UnsupportedDatum { datum_type: u16 },

    #[error("Unsupported key protector type: {protector_type:#06x}")]
    UnsupportedProtector { protector_type: u16 },

    #[error("Unsupported encryption method: {method:#06x}")]
    UnsupportedEncryptionMethod { method: u16 },

    #[error("Invalid credential format: {detail}")]
    InvalidCredentialFormat { detail: &'static str },

    #[error("AES-CCM key unwrap failed (wrong key or corrupt data)")]
    KeyUnwrapFailed,

    #[error("Authentication failed (wrong credential)")]
    AuthenticationFailed,

    #[error("Sector layout error: {detail}")]
    SectorLayoutError { detail: &'static str },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataFailure {
    #[error("Invalid FVE signature")]
    InvalidSignature,

    #[error("CRC-32 integrity check failed")]
    CrcMismatch,

    #[error("Size bounds exceeded: declared {declared} bytes, only {available} available")]
    SizeBoundsExceeded { declared: u64, available: u64 },

    #[error("Parse failed at offset {offset:#x}: {detail}")]
    ParseFailed { offset: u64, detail: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_failure_display() {
        let f = MetadataFailure::InvalidSignature;
        let msg = f.to_string();
        assert!(msg.contains("signature"), "{msg}");
    }

    #[test]
    fn metadata_failure_crc_mismatch() {
        let f = MetadataFailure::CrcMismatch;
        let msg = f.to_string();
        assert!(msg.contains("CRC"), "{msg}");
    }

    #[test]
    fn bitlocker_error_unsupported_version() {
        let e = BitLockerError::UnsupportedVersion { version: 99 };
        let msg = e.to_string();
        assert!(msg.contains("99"), "{msg}");
    }

    #[test]
    fn bitlocker_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = BitLockerError::from(io_err);
        let msg = e.to_string();
        assert!(msg.contains("gone"), "{msg}");
    }

    #[test]
    fn bitlocker_error_all_corrupt() {
        let e = BitLockerError::AllMetadataBlocksCorrupt {
            failures: [
                MetadataFailure::InvalidSignature,
                MetadataFailure::CrcMismatch,
                MetadataFailure::SizeBoundsExceeded {
                    declared: 1000,
                    available: 512,
                },
            ],
        };
        let msg = e.to_string();
        assert!(msg.contains("metadata"), "{msg}");
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());

        let err: Result<u32> = Err(BitLockerError::AuthenticationFailed);
        assert!(err.is_err());
    }
}
