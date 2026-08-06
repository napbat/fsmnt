use super::{
    ArrayVec, FromBytes, MAX_PATH_BUFFER_SIZE, NFS_DEVICE_DATA_SIZE, NFS_REPARSE_DATA_HEADER_SIZE,
    NfsDeviceData, NfsReparseDataHeader, NtfsError, NtfsPosition, NtfsReparsePoint, Result,
    nfs_types, reparse_tags,
};

/// Parsed NFS reparse point representing a POSIX special file.
///
/// NFS reparse points encode POSIX file types not native to NTFS. The
/// reparse data contains an 8-byte type field followed by type-specific
/// data.
///
/// Reference: [MS-FSCC] 2.1.2.6
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NtfsNfsReparsePoint {
    /// POSIX symbolic link with a Unicode (UTF-16LE) target path.
    SymbolicLink {
        /// Target path as UTF-16LE bytes (not null-terminated).
        target: alloc::boxed::Box<ArrayVec<u8, MAX_PATH_BUFFER_SIZE>>,
    },
    /// Character special device with major and minor numbers.
    CharacterDevice {
        /// Major device number.
        major: u32,
        /// Minor device number.
        minor: u32,
    },
    /// Block special device with major and minor numbers.
    BlockDevice {
        /// Major device number.
        major: u32,
        /// Minor device number.
        minor: u32,
    },
    /// FIFO (named pipe).
    Fifo,
    /// Socket.
    Socket,
}

impl NtfsNfsReparsePoint {
    pub(super) fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::NFS {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::NFS,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < NFS_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "NFS reparse data too small for header",
            });
        }

        let header = NfsReparseDataHeader::read_from_bytes(&data[..NFS_REPARSE_DATA_HEADER_SIZE])
            .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse NFS reparse header",
        })?;

        let nfs_type = header.nfs_type.get();
        let payload = &data[NFS_REPARSE_DATA_HEADER_SIZE..];

        match nfs_type {
            nfs_types::NFS_SPECFILE_LNK => {
                let mut target = ArrayVec::new();
                target.try_extend_from_slice(payload).map_err(|_| {
                    NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS symlink target path too large",
                    }
                })?;
                Ok(Self::SymbolicLink {
                    target: alloc::boxed::Box::new(target),
                })
            }
            nfs_types::NFS_SPECFILE_CHR => {
                if payload.len() < NFS_DEVICE_DATA_SIZE {
                    return Err(NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS character device data too small",
                    });
                }
                let dev = NfsDeviceData::read_from_bytes(&payload[..NFS_DEVICE_DATA_SIZE])
                    .map_err(|_| NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "failed to parse NFS character device data",
                    })?;
                Ok(Self::CharacterDevice {
                    major: dev.major.get(),
                    minor: dev.minor.get(),
                })
            }
            nfs_types::NFS_SPECFILE_BLK => {
                if payload.len() < NFS_DEVICE_DATA_SIZE {
                    return Err(NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS block device data too small",
                    });
                }
                let dev = NfsDeviceData::read_from_bytes(&payload[..NFS_DEVICE_DATA_SIZE])
                    .map_err(|_| NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "failed to parse NFS block device data",
                    })?;
                Ok(Self::BlockDevice {
                    major: dev.major.get(),
                    minor: dev.minor.get(),
                })
            }
            nfs_types::NFS_SPECFILE_FIFO => Ok(Self::Fifo),
            nfs_types::NFS_SPECFILE_SOCK => Ok(Self::Socket),
            _ => Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unknown NFS special file type",
            }),
        }
    }

    /// Returns the NFS type constant for this reparse point.
    #[must_use]
    pub fn nfs_type(&self) -> u64 {
        match self {
            Self::SymbolicLink { .. } => nfs_types::NFS_SPECFILE_LNK,
            Self::CharacterDevice { .. } => nfs_types::NFS_SPECFILE_CHR,
            Self::BlockDevice { .. } => nfs_types::NFS_SPECFILE_BLK,
            Self::Fifo => nfs_types::NFS_SPECFILE_FIFO,
            Self::Socket => nfs_types::NFS_SPECFILE_SOCK,
        }
    }

    /// Returns the symlink target as raw UTF-16LE bytes.
    ///
    /// Returns `None` if this is not a symbolic link.
    #[must_use]
    pub fn target_path_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::SymbolicLink { target } => Some(target),
            _ => None,
        }
    }

    /// Decodes the symlink target to a String.
    ///
    /// Returns `None` if this is not a symbolic link.
    #[must_use]
    pub fn target_path(&self) -> Option<Result<alloc::string::String>> {
        match self {
            Self::SymbolicLink { target } => Some(decode_utf16le(target)),
            _ => None,
        }
    }

    /// Returns the major device number.
    ///
    /// Returns `None` if this is not a character or block device.
    #[must_use]
    pub fn major(&self) -> Option<u32> {
        match self {
            Self::CharacterDevice { major, .. } | Self::BlockDevice { major, .. } => Some(*major),
            _ => None,
        }
    }

    /// Returns the minor device number.
    ///
    /// Returns `None` if this is not a character or block device.
    #[must_use]
    pub fn minor(&self) -> Option<u32> {
        match self {
            Self::CharacterDevice { minor, .. } | Self::BlockDevice { minor, .. } => Some(*minor),
            _ => None,
        }
    }
}

/// Splits a UTF-16LE byte buffer on null terminators (U+0000).
///
/// Returns slices of the content between null terminators, excluding the
/// null terminators themselves. Handles the common case where the final
/// string may or may not have a trailing null.
///
/// Returns an error if the data has an odd number of bytes, since
/// UTF-16LE requires 2-byte alignment.
// mutants::skip: the loop guard `i + 1 < data.len()` has two equivalent
// mutations. After the odd-length early return, `data.len()` is always even
// and `i` always even (starts 0, `i += 2`), so `i + 1` is always odd and can
// never equal `data.len()`. Therefore `< -> <=` (differs only at
// `i + 1 == len`) and `+ -> *` on the guard (`i * 1 == i`, and `i < len` ⟺
// `i + 1 < len` for even i and even len) produce identical behaviour for every
// input — provably equivalent. The killable index mutation `data[i + 1]`
// (1278) is covered by test_split_utf16le_high_byte_not_a_terminator and the
// non-terminating `i += 2 -> i *= 2` mutation (1282) is caught by the harness
// timeout; both are exercised, but the fn must be skipped wholesale because
// `#[mutants::skip]` cannot target a single expression.
#[cfg_attr(test, mutants::skip)]
pub(super) fn split_utf16le_null_terminated(data: &[u8]) -> Result<alloc::vec::Vec<&[u8]>> {
    if !data.len().is_multiple_of(2) {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "UTF-16LE string data has odd number of bytes",
        });
    }

    let mut result = alloc::vec::Vec::new();
    let mut start = 0;

    // Walk in 2-byte steps looking for U+0000 (0x00, 0x00)
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            result.push(&data[start..i]);
            start = i + 2;
        }
        i += 2;
    }

    // If there's a trailing string without a null terminator, include it
    if start < data.len() {
        result.push(&data[start..]);
    }

    Ok(result)
}

/// Decodes UTF-16LE bytes to a String.
pub(in crate::structured_values::reparse) fn decode_utf16le(
    bytes: &[u8],
) -> Result<alloc::string::String> {
    use alloc::string::String;
    use alloc::vec::Vec;

    if !bytes.len().is_multiple_of(2) {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "UTF-16LE data has odd number of bytes",
        });
    }

    let u16_iter = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));

    let chars: Vec<u16> = u16_iter.collect();
    String::from_utf16(&chars).map_err(|_| NtfsError::InvalidReparsePointData {
        position: NtfsPosition::none(),
        reason: "invalid UTF-16LE data",
    })
}
