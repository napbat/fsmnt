//! Windows Overlay Filter (WOF) reparse point structures.
//!
//! WOF reparse points (tag `IO_REPARSE_TAG_WOF`, 0x80000017) identify files
//! whose data is stored compressed via the Windows Overlay Filter driver.
//! The reparse data contains a `WOF_EXTERNAL_INFO` header followed by a
//! provider-specific payload.
//!
//! This module parses the metadata only -- actual decompression of the
//! `:WofCompressedData` alternate data stream is handled elsewhere.
//!
//! Reference: MS-FSCC and Windows SDK `wofapi.h`.

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, Unaligned};

use crate::error::{NtfsError, Result};
use crate::structured_values::reparse::reparse_point::{NtfsReparsePoint, reparse_tags};
use crate::types::NtfsPosition;

/// Size of [`WofExternalInfo`] in bytes.
const WOF_EXTERNAL_INFO_SIZE: usize = 8;

/// Size of [`FileProviderExternalInfoV1`] in bytes.
const FILE_PROVIDER_EXTERNAL_INFO_V1_SIZE: usize = 8;

/// `WOF_EXTERNAL_INFO` header (8 bytes).
///
/// First structure in the reparse data buffer for WOF reparse points.
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub(crate) struct WofExternalInfo {
    /// Structure version. Must be 1 (`WOF_CURRENT_VERSION`).
    pub version: U32<LittleEndian>,
    /// Compression provider identifier (see [`WofProvider`]).
    pub provider: U32<LittleEndian>,
}

/// `FILE_PROVIDER_EXTERNAL_INFO_V1` (8 bytes).
///
/// Provider-specific payload for `WofProvider::File` (provider 2).
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub(crate) struct FileProviderExternalInfoV1 {
    /// Structure version. Must be 1.
    pub version: U32<LittleEndian>,
    /// Compression algorithm (see [`WofAlgorithm`]).
    pub algorithm: U32<LittleEndian>,
}

/// WOF compression provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WofProvider {
    /// WIM backing provider (wimboot).
    Wim = 1,
    /// Individually compressed file provider.
    File = 2,
}

impl WofProvider {
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(Self::Wim),
            2 => Ok(Self::File),
            _ => Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unknown WOF provider",
            }),
        }
    }
}

/// WOF file compression algorithm.
///
/// Identifies the algorithm used to compress chunks in the
/// `:WofCompressedData` alternate data stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WofAlgorithm {
    /// XPRESS with 4 KB chunks.
    Xpress4K = 0,
    /// LZX with 32 KB chunks.
    Lzx = 1,
    /// XPRESS with 8 KB chunks.
    Xpress8K = 2,
    /// XPRESS with 16 KB chunks.
    Xpress16K = 3,
}

impl WofAlgorithm {
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Xpress4K),
            1 => Ok(Self::Lzx),
            2 => Ok(Self::Xpress8K),
            3 => Ok(Self::Xpress16K),
            _ => Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unknown WOF compression algorithm",
            }),
        }
    }

    /// Decompressed chunk size in bytes.
    pub fn chunk_size(self) -> u32 {
        match self {
            Self::Xpress4K => 4096,
            Self::Lzx => 32768,
            Self::Xpress8K => 8192,
            Self::Xpress16K => 16384,
        }
    }

    /// Convert to `nt_compression::Algorithm`.
    pub(crate) fn to_nt_algorithm(self) -> nt_compression::Algorithm {
        match self {
            Self::Xpress4K | Self::Xpress8K | Self::Xpress16K => nt_compression::Algorithm::Xpress,
            Self::Lzx => nt_compression::Algorithm::Lzx,
        }
    }
}

/// Parsed WOF reparse point metadata.
///
/// Contains the provider and (for file-provider reparse points) the
/// compression algorithm. Obtain via [`NtfsReparsePoint::wof_info`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WofInfo {
    /// Which WOF provider backs this file.
    pub provider: WofProvider,
    /// Compression algorithm (only meaningful for `WofProvider::File`).
    pub algorithm: WofAlgorithm,
}

impl NtfsReparsePoint {
    /// Parse WOF reparse point data, if this is a WOF reparse point.
    ///
    /// Returns `None` if the tag is not `IO_REPARSE_TAG_WOF`.
    /// Returns `Some(Err(_))` if the tag matches but the data is malformed.
    pub fn wof_info(&self) -> Option<Result<WofInfo>> {
        if self.tag() != reparse_tags::WOF {
            return None;
        }
        Some(parse_wof_data(self.data()))
    }
}

fn parse_wof_data(data: &[u8]) -> Result<WofInfo> {
    if data.len() < WOF_EXTERNAL_INFO_SIZE {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "WOF reparse data too small for WOF_EXTERNAL_INFO",
        });
    }

    let header =
        WofExternalInfo::read_from_bytes(&data[..WOF_EXTERNAL_INFO_SIZE]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to parse WOF_EXTERNAL_INFO",
            }
        })?;

    if header.version.get() != 1 {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "unsupported WOF_EXTERNAL_INFO version (expected 1)",
        });
    }

    let provider = WofProvider::from_u32(header.provider.get())?;

    let algorithm = match provider {
        WofProvider::File => {
            let provider_data_start = WOF_EXTERNAL_INFO_SIZE;
            let provider_data_end = provider_data_start + FILE_PROVIDER_EXTERNAL_INFO_V1_SIZE;

            if data.len() < provider_data_end {
                return Err(NtfsError::InvalidReparsePointData {
                    position: NtfsPosition::none(),
                    reason: "WOF reparse data too small for \
                             FILE_PROVIDER_EXTERNAL_INFO_V1",
                });
            }

            let file_info = FileProviderExternalInfoV1::read_from_bytes(
                &data[provider_data_start..provider_data_end],
            )
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to parse FILE_PROVIDER_EXTERNAL_INFO_V1",
            })?;

            if file_info.version.get() != 1 {
                return Err(NtfsError::InvalidReparsePointData {
                    position: NtfsPosition::none(),
                    reason: "unsupported FILE_PROVIDER_EXTERNAL_INFO \
                             version (expected 1)",
                });
            }

            WofAlgorithm::from_u32(file_info.algorithm.get())?
        }
        WofProvider::Wim => WofAlgorithm::Xpress4K,
    };

    Ok(WofInfo {
        provider,
        algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build raw WOF reparse point bytes (header + data) for testing.
    fn make_wof_reparse_bytes(reparse_data: &[u8]) -> alloc::vec::Vec<u8> {
        let tag = reparse_tags::WOF.to_le_bytes();
        let data_len = (reparse_data.len() as u16).to_le_bytes();
        let reserved = [0u8; 2];

        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&tag);
        buf.extend_from_slice(&data_len);
        buf.extend_from_slice(&reserved);
        buf.extend_from_slice(reparse_data);
        buf
    }

    fn wof_external_info_bytes(version: u32, provider: u32) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&version.to_le_bytes());
        buf[4..8].copy_from_slice(&provider.to_le_bytes());
        buf
    }

    fn file_provider_info_bytes(version: u32, algorithm: u32) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&version.to_le_bytes());
        buf[4..8].copy_from_slice(&algorithm.to_le_bytes());
        buf
    }

    #[test]
    fn parse_wof_external_info() {
        let bytes = wof_external_info_bytes(1, 2);
        let header = WofExternalInfo::read_from_bytes(&bytes).expect("valid parse");
        assert_eq!(header.version.get(), 1);
        assert_eq!(header.provider.get(), 2);
    }

    #[test]
    fn parse_file_provider_info() {
        let bytes = file_provider_info_bytes(1, 3);
        let header = FileProviderExternalInfoV1::read_from_bytes(&bytes).expect("valid parse");
        assert_eq!(header.version.get(), 1);
        assert_eq!(header.algorithm.get(), 3);
    }

    #[test]
    fn invalid_wof_version_returns_error() {
        let wof = wof_external_info_bytes(2, 2);
        let fp = file_provider_info_bytes(1, 0);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("bad version");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("unsupported WOF_EXTERNAL_INFO version"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn invalid_provider_returns_error() {
        let wof = wof_external_info_bytes(1, 99);
        let raw = make_wof_reparse_bytes(&wof);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("bad provider");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("unknown WOF provider"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn unknown_algorithm_returns_error() {
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(1, 42);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("bad algorithm");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("unknown WOF compression algorithm"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn all_algorithm_chunk_sizes() {
        assert_eq!(WofAlgorithm::Xpress4K.chunk_size(), 4096);
        assert_eq!(WofAlgorithm::Lzx.chunk_size(), 32768);
        assert_eq!(WofAlgorithm::Xpress8K.chunk_size(), 8192);
        assert_eq!(WofAlgorithm::Xpress16K.chunk_size(), 16384);
    }

    #[test]
    fn wof_info_returns_none_for_non_wof_tag() {
        let tag = reparse_tags::SYMLINK.to_le_bytes();
        let data_len = 0u16.to_le_bytes();
        let reserved = [0u8; 2];
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&tag);
        buf.extend_from_slice(&data_len);
        buf.extend_from_slice(&reserved);

        let rp =
            NtfsReparsePoint::from_bytes(&buf, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.wof_info().is_none());
    }

    #[test]
    fn round_trip_file_provider_xpress4k() {
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(1, 0);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.wof_info().expect("is WOF").expect("valid data");
        assert_eq!(info.provider, WofProvider::File);
        assert_eq!(info.algorithm, WofAlgorithm::Xpress4K);
    }

    #[test]
    fn round_trip_file_provider_lzx() {
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(1, 1);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.wof_info().expect("is WOF").expect("valid data");
        assert_eq!(info.provider, WofProvider::File);
        assert_eq!(info.algorithm, WofAlgorithm::Lzx);
        assert_eq!(info.algorithm.chunk_size(), 32768);
    }

    #[test]
    fn round_trip_file_provider_xpress8k() {
        // Algorithm 2 (Xpress8K) must round-trip through `from_u32`'s
        // match arm 2; deleting it would fall through to the error case.
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(1, 2);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.wof_info().expect("is WOF").expect("valid data");
        assert_eq!(info.provider, WofProvider::File);
        assert_eq!(info.algorithm, WofAlgorithm::Xpress8K);
        assert_eq!(info.algorithm.chunk_size(), 8192);
    }

    #[test]
    fn round_trip_file_provider_xpress16k() {
        // Algorithm 3 (Xpress16K) must round-trip through `from_u32`'s
        // match arm 3; deleting it would fall through to the error case.
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(1, 3);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.wof_info().expect("is WOF").expect("valid data");
        assert_eq!(info.provider, WofProvider::File);
        assert_eq!(info.algorithm, WofAlgorithm::Xpress16K);
        assert_eq!(info.algorithm.chunk_size(), 16384);
    }

    #[test]
    fn round_trip_wim_provider() {
        let wof = wof_external_info_bytes(1, 1);
        let raw = make_wof_reparse_bytes(&wof);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.wof_info().expect("is WOF").expect("valid data");
        assert_eq!(info.provider, WofProvider::Wim);
    }

    #[test]
    fn data_too_small_for_wof_header() {
        let raw = make_wof_reparse_bytes(&[0u8; 4]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("data too small");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("too small for WOF_EXTERNAL_INFO"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn data_too_small_for_file_provider() {
        let wof = wof_external_info_bytes(1, 2);
        let raw = make_wof_reparse_bytes(&wof);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("data too small");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("too small for FILE_PROVIDER_EXTERNAL_INFO_V1"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn invalid_file_provider_version_returns_error() {
        let wof = wof_external_info_bytes(1, 2);
        let fp = file_provider_info_bytes(99, 0);
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&wof);
        data.extend_from_slice(&fp);

        let raw = make_wof_reparse_bytes(&data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.wof_info().expect("is WOF").expect_err("bad fp version");
        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("unsupported FILE_PROVIDER_EXTERNAL_INFO version"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn to_nt_algorithm_mapping() {
        assert_eq!(
            WofAlgorithm::Xpress4K.to_nt_algorithm(),
            nt_compression::Algorithm::Xpress,
        );
        assert_eq!(
            WofAlgorithm::Xpress8K.to_nt_algorithm(),
            nt_compression::Algorithm::Xpress,
        );
        assert_eq!(
            WofAlgorithm::Xpress16K.to_nt_algorithm(),
            nt_compression::Algorithm::Xpress,
        );
        assert_eq!(
            WofAlgorithm::Lzx.to_nt_algorithm(),
            nt_compression::Algorithm::Lzx,
        );
    }
}
