/// Result type returned by `BitLocker` parsing and unlock operations.
pub type Result<T, E = BitLockerError> = std::result::Result<T, E>;

/// Errors raised while parsing, unlocking, or reading a `BitLocker` volume.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BitLockerError {
    /// One of the redundant FVE metadata blocks failed validation.
    #[error("Invalid FVE metadata in block {block_index}: {reason}")]
    InvalidMetadata {
        /// Zero-based index of the invalid metadata block.
        block_index: u8,
        /// Validation failure found in the block.
        reason: MetadataFailure,
    },

    /// None of the volume's three redundant metadata blocks was usable.
    #[error("All three FVE metadata blocks are corrupt: [0] {}, [1] {}, [2] {}", failures[0], failures[1], failures[2])]
    AllMetadataBlocksCorrupt {
        /// Failure reported for each metadata block in on-disk order.
        failures: [MetadataFailure; 3],
    },

    /// The volume uses a `BitLocker` metadata version this crate cannot parse.
    #[error("Unsupported BitLocker version: {version}")]
    UnsupportedVersion {
        /// Unsupported on-disk metadata version.
        version: u16,
    },

    /// An FVE datum carries an unimplemented value type.
    #[error("Unsupported FVE datum type: {datum_type:#06x}")]
    UnsupportedDatum {
        /// Numeric datum type read from the metadata.
        datum_type: u16,
    },

    /// The requested key-protector mechanism is not implemented.
    #[error("Unsupported key protector type: {protector_type:#06x}")]
    UnsupportedProtector {
        /// Numeric protector type read from the VMK datum.
        protector_type: u16,
    },

    /// The volume uses an encryption algorithm this crate cannot decrypt.
    #[error("Unsupported encryption method: {method:#06x}")]
    UnsupportedEncryptionMethod {
        /// Numeric encryption method read from the FVE dataset.
        method: u16,
    },

    /// A password, recovery key, or startup-key file has invalid syntax.
    #[error("Invalid credential format: {detail}")]
    InvalidCredentialFormat {
        /// Static explanation of the malformed credential.
        detail: &'static str,
    },

    /// AES-CCM could not authenticate and unwrap protected key material.
    #[error("AES-CCM key unwrap failed (wrong key or corrupt data)")]
    KeyUnwrapFailed,

    /// The supplied credential did not unlock any matching key protector.
    #[error("Authentication failed (wrong credential)")]
    AuthenticationFailed,

    /// Encrypted-sector geometry is inconsistent or unsupported.
    #[error("Sector layout error: {detail}")]
    SectorLayoutError {
        /// Static explanation of the invalid sector layout.
        detail: &'static str,
    },

    /// An error from the underlying volume reader.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Reason an individual redundant FVE metadata block was rejected.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataFailure {
    /// The block does not begin with the FVE metadata signature.
    #[error("Invalid FVE signature")]
    InvalidSignature,

    /// The stored metadata CRC-32 does not match the block contents.
    #[error("CRC-32 integrity check failed")]
    CrcMismatch,

    /// A declared structure or block size exceeds the available bytes.
    #[error("Size bounds exceeded: declared {declared} bytes, only {available} available")]
    SizeBoundsExceeded {
        /// Size declared by the on-disk structure.
        declared: u64,
        /// Number of bytes available in the containing buffer.
        available: u64,
    },

    /// A field could not be parsed at a known volume offset.
    #[error("Parse failed at offset {offset:#x}: {detail}")]
    ParseFailed {
        /// Byte offset associated with the parse failure.
        offset: u64,
        /// Static explanation of the malformed field.
        detail: &'static str,
    },
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
