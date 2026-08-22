//! Compressed non-resident attribute value reader with LZNT1 decompression.

use alloc::vec::Vec;

use super::attribute_list_non_resident::NtfsAttributeListNonResidentAttributeValue;
use super::non_resident::NtfsNonResidentAttributeValue;
use super::owned::NtfsAttributeValueOwned;
use super::seek_contiguous;
use fsmnt_parser_core::io::FsReadSeek;

use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;

/// Controls how compression errors are handled during decompression.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompressionRecoveryMode {
    /// Stop on first decompression error (default behavior).
    #[default]
    Strict,
    /// Attempt to recover partial data from damaged compression units.
    /// Decompresses as much as possible, zero-fills the remainder.
    BestEffort,
}

/// Reader for compressed non-resident attribute values.
///
/// This type wraps a non-resident attribute value and transparently
/// decompresses data using the LZNT1 algorithm as it is read.
#[derive(Clone, Debug)]
pub struct NtfsCompressedNonResidentAttributeValue<'n> {
    /// Filesystem geometry and collation state associated with the value.
    ntfs: &'n Ntfs,
    /// Decoded mapping of logical compression-unit bytes to disk extents.
    map: DataRunMap,
    /// Size of a compression unit in bytes (typically 64KB)
    compression_unit_size: u64,
    /// Decompressed data size (from attribute header)
    decompressed_size: u64,
    /// Size of the initialized portion of the decompressed data.
    /// Bytes beyond this offset (up to `decompressed_size`) read as zero.
    initialized_size: u64,
    /// How to handle decompression errors
    recovery_mode: CompressionRecoveryMode,
    /// Current position in the decompressed stream
    stream_position: u64,
    /// Buffer for reading compressed data (one compression unit)
    compressed_buffer: Vec<u8>,
    /// Buffer for decompressed data (one compression unit)
    decompressed_buffer: Vec<u8>,
    /// Index of the currently buffered compression unit.
    buffered_unit: Option<u64>,
}

impl<'n> NtfsCompressedNonResidentAttributeValue<'n> {
    /// Creates a new compressed value reader.
    ///
    /// # Panics
    ///
    /// Panics when the compression-unit size is zero or exceeds the target's
    /// addressable memory. Valid NTFS compression units satisfy both bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the attribute's data-run stream is malformed.
    pub fn new(
        inner: &NtfsNonResidentAttributeValue<'n, '_>,
        compression_unit_size: u64,
        decompressed_size: u64,
        initialized_size: u64,
    ) -> Result<Self> {
        let ntfs = inner.ntfs();
        let map = DataRunMap::from_data_runs(inner.data_runs())?;
        Ok(Self::from_map(
            ntfs,
            map,
            compression_unit_size,
            decompressed_size,
            initialized_size,
        ))
    }

    fn from_map(
        ntfs: &'n Ntfs,
        map: DataRunMap,
        compression_unit_size: u64,
        decompressed_size: u64,
        initialized_size: u64,
    ) -> Self {
        assert!(
            compression_unit_size != 0,
            "an NTFS compression unit cannot be empty"
        );
        let cu_size = usize::try_from(compression_unit_size)
            .expect("an NTFS compression unit must fit in addressable memory");
        Self {
            ntfs,
            map,
            compression_unit_size,
            decompressed_size,
            initialized_size: initialized_size.min(decompressed_size),
            recovery_mode: CompressionRecoveryMode::default(),
            stream_position: 0,
            compressed_buffer: alloc::vec![0u8; cu_size],
            decompressed_buffer: alloc::vec![0u8; cu_size],
            buffered_unit: None,
        }
    }

    pub(crate) fn from_attribute_list<T: Read + Seek>(
        inner: &NtfsAttributeListNonResidentAttributeValue<'n, '_>,
        fs: &mut T,
        compression_unit_size: u64,
        decompressed_size: u64,
        initialized_size: u64,
    ) -> Result<Self> {
        let map = inner.data_run_map(fs)?;
        Ok(Self::from_map(
            inner.ntfs(),
            map,
            compression_unit_size,
            decompressed_size,
            initialized_size,
        ))
    }

    /// Returns `true` if the attribute value contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decompressed_size == 0
    }

    /// Returns the total length of the decompressed attribute value, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.decompressed_size
    }

    /// Returns the current stream position within this value, in bytes.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_position
    }

    /// Returns the [`Ntfs`] object reference associated to this value.
    ///
    /// [`Ntfs`]: crate::Ntfs
    #[must_use]
    pub fn ntfs(&self) -> &'n crate::ntfs::Ntfs {
        self.ntfs
    }

    /// Sets the compression error recovery mode.
    ///
    /// In [`CompressionRecoveryMode::BestEffort`] mode, decompression errors
    /// are recovered by zero-filling damaged compression units instead of
    /// returning an error.
    pub fn set_recovery_mode(&mut self, mode: CompressionRecoveryMode) {
        self.recovery_mode = mode;
    }

    /// Detaches this compressed value from its file record while preserving
    /// its reusable compression-unit work buffers.
    pub(super) fn into_owned(self) -> NtfsAttributeValueOwned {
        let Self {
            map,
            compression_unit_size,
            decompressed_size,
            initialized_size,
            recovery_mode,
            compressed_buffer,
            decompressed_buffer,
            ..
        } = self;
        NtfsAttributeValueOwned::compressed(
            map,
            compression_unit_size,
            decompressed_size,
            initialized_size,
            recovery_mode,
            compressed_buffer,
            decompressed_buffer,
        )
    }

    /// Ensures the compression unit containing `position` is decompressed.
    fn ensure_unit_buffered<T>(&mut self, fs: &mut T, position: u64) -> Result<()>
    where
        T: Read + Seek,
    {
        let unit_index = position / self.compression_unit_size;

        if self.buffered_unit == Some(unit_index) {
            return Ok(()); // Already buffered
        }

        let raw_offset = unit_index * self.compression_unit_size;

        // Read the compression unit. In BestEffort mode, I/O errors
        // result in a zero-filled buffer instead of propagating.
        let bytes_read =
            match self
                .map
                .read_allocated_prefix_at(fs, raw_offset, &mut self.compressed_buffer)
            {
                Ok(n) => n,
                Err(e) => {
                    if self.recovery_mode == CompressionRecoveryMode::BestEffort {
                        self.decompressed_buffer.fill(0);
                        self.enforce_initialized_size(unit_index);
                        self.buffered_unit = Some(unit_index);
                        return Ok(());
                    }
                    return Err(e);
                }
            };

        if bytes_read == 0 {
            // Past end of data — zero-fill.
            self.decompressed_buffer.fill(0);
        } else if bytes_read == self.compressed_buffer.len() {
            // Full unit read — data is uncompressed (incompressible).
            self.decompressed_buffer[..bytes_read]
                .copy_from_slice(&self.compressed_buffer[..bytes_read]);
        } else {
            // Partial read — data is compressed, decompress it.
            match self.recovery_mode {
                CompressionRecoveryMode::Strict => {
                    self.decompress_unit(bytes_read)?;
                }
                CompressionRecoveryMode::BestEffort => {
                    crate::compression_recovery::decompress_lznt1_lenient(
                        &self.compressed_buffer[..bytes_read],
                        &mut self.decompressed_buffer,
                    );
                }
            }
        }

        // Enforce initialized_size: zero bytes beyond initialized_size.
        self.enforce_initialized_size(unit_index);

        self.buffered_unit = Some(unit_index);
        Ok(())
    }

    /// Zeros bytes in the decompressed buffer that are beyond `initialized_size`.
    // mutants::skip: the `unit_end > initialized_size` (line 166) and
    // `zero_from < buffer.len()` (line 168) guards have provably-equivalent
    // boundary flips. When `unit_end == initialized_size`, `zero_from` is
    // exactly `buffer.len()`, so the inner guard skips the fill regardless of
    // `>` vs `>=`; and flipping that inner `<` to `<=` only ever fills the
    // empty tail slice `buffer[len..]`, a no-op. The observable behavior —
    // real bytes through `initialized_size`, zeros beyond it within a unit —
    // is pinned by `enforce_initialized_size_zeros_within_first_unit` and
    // `read_returns_initialized_bytes_then_zeros`.
    #[cfg_attr(test, mutants::skip)]
    fn enforce_initialized_size(&mut self, unit_index: u64) {
        let unit_start = unit_index * self.compression_unit_size;
        let unit_end = unit_start + self.compression_unit_size;
        if unit_end > self.initialized_size {
            let zero_from = usize::try_from(self.initialized_size.saturating_sub(unit_start))
                .unwrap_or(usize::MAX);
            if zero_from < self.decompressed_buffer.len() {
                self.decompressed_buffer[zero_from..].fill(0);
            }
        }
    }

    /// Decompresses the current compression unit using LZNT1.
    #[cfg(feature = "compression")]
    fn decompress_unit(&mut self, compressed_len: usize) -> Result<()> {
        self.decompressed_buffer.fill(0);

        nt_compression::lznt1::decompress(
            &self.compressed_buffer[..compressed_len],
            &mut self.decompressed_buffer,
        )
        .map(|_bytes_written| ())
        .map_err(|e| NtfsError::DecompressionError {
            message: alloc::format!("{e}"),
        })
    }

    // mutants::skip: this body only compiles when the `compression` feature is
    // off. The verify gate runs with `--all-features`, so this code is cfg'd
    // out and any mutation of it is a no-op (provably equivalent under the
    // test configuration). The active `#[cfg(feature = "compression")]` variant
    // above is covered by `strict_mode_decompresses_partial_unit`.
    #[cfg(not(feature = "compression"))]
    #[cfg_attr(test, mutants::skip)]
    fn decompress_unit(&mut self, _compressed_len: usize) -> Result<()> {
        Err(NtfsError::UnsupportedFeature {
            feature: "compression",
        })
    }
}

impl<R: Read + Seek> FsReadSeek<R> for NtfsCompressedNonResidentAttributeValue<'_> {
    type Error = NtfsError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        if self.stream_position >= self.decompressed_size {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < buf.len() && self.stream_position < self.decompressed_size {
            // Ensure we have the right compression unit buffered
            self.ensure_unit_buffered(fs, self.stream_position)?;

            // Calculate position within the decompressed buffer
            let offset_in_unit = usize::try_from(self.stream_position % self.compression_unit_size)
                .expect("a buffered compression-unit offset fits usize");
            let remaining_in_unit = self.decompressed_buffer.len() - offset_in_unit;
            let remaining_in_file = usize::try_from(self.decompressed_size - self.stream_position)
                .unwrap_or(usize::MAX);
            let remaining_in_buf = buf.len() - bytes_read;

            let to_copy = remaining_in_unit
                .min(remaining_in_file)
                .min(remaining_in_buf);

            buf[bytes_read..bytes_read + to_copy].copy_from_slice(
                &self.decompressed_buffer[offset_in_unit..offset_in_unit + to_copy],
            );

            bytes_read += to_copy;
            self.stream_position += u64::try_from(to_copy).expect("a copied slice length fits u64");
        }

        Ok(bytes_read)
    }

    fn seek(&mut self, _fs: &mut R, pos: SeekFrom) -> Result<u64> {
        seek_contiguous(&mut self.stream_position, self.decompressed_size, pos)
    }

    fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn len(&self) -> u64 {
        self.decompressed_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::Ntfs;

    /// A reader that serves the boot sector and any offset below the data
    /// run, but returns an I/O error for reads at or beyond the data run.
    /// Used to exercise the I/O-error recovery branch in `ensure_unit_buffered`.
    struct FailingReader {
        inner: fsmnt_testkit::Cursor<std::vec::Vec<u8>>,
    }

    impl crate::io::Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
            if self.inner.position() >= DATA_RUN_LCN * CLUSTER_SIZE {
                return Err(std::io::Error::other("synthetic read failure"));
            }
            self.inner.read(buf)
        }
    }

    impl crate::io::Seek for FailingReader {
        fn seek(&mut self, pos: SeekFrom) -> crate::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    const CLUSTER_SIZE: u64 = 512;
    /// Byte offset of the data-run's first cluster in the backing image
    /// (LCN 4 * 512). The synthetic attribute data lives here.
    const DATA_RUN_LCN: u64 = 4;
    const DATA_RUN_CLUSTERS: u64 = 8;

    /// Builds a 512-byte NTFS boot sector with 512-byte clusters, then fills
    /// the backing image so the single data run at LCN 4 holds `payload`.
    ///
    /// Returns the in-memory reader and a constructed [`Ntfs`].
    fn build_image(payload: &[u8]) -> fsmnt_testkit::Cursor<std::vec::Vec<u8>> {
        let image_len = usize::try_from(DATA_RUN_LCN + DATA_RUN_CLUSTERS)
            .expect("test value fits usize")
            * usize::try_from(CLUSTER_SIZE).expect("test value fits usize");
        let mut buf = std::vec![0u8; image_len];
        // Boot sector: NTFS OEM, 512-byte sectors, 1 sector/cluster.
        buf[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 1; // sectors_per_cluster -> cluster_size 512
        let image_len = u64::try_from(image_len).expect("test image length fits in u64");
        buf[0x28..0x30].copy_from_slice(&(image_len / 512).to_le_bytes());
        buf[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
        buf[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
        buf[0x40] = (-10i8).cast_unsigned();
        buf[0x48..0x50].copy_from_slice(&0xCAFEu64.to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;

        // Place the attribute payload at LCN 4.
        let start = usize::try_from(DATA_RUN_LCN * CLUSTER_SIZE).expect("test value fits usize");
        buf[start..start + payload.len()].copy_from_slice(payload);
        fsmnt_testkit::Cursor::new(buf)
    }

    /// A single data run: 1-byte cluster count, 1-byte VCN (the LCN).
    fn data_run_bytes() -> std::vec::Vec<u8> {
        // header 0x11: upper nibble 1 (vcn bytes), lower nibble 1 (count bytes).
        std::vec![
            0x11,
            u8::try_from(DATA_RUN_CLUSTERS).expect("test value fits u8"),
            u8::try_from(DATA_RUN_LCN).expect("test value fits u8"),
            0x00
        ]
    }

    /// One allocated cluster followed by a seven-cluster sparse tail.
    fn compressed_data_run_bytes() -> std::vec::Vec<u8> {
        std::vec![
            0x11,
            1,
            u8::try_from(DATA_RUN_LCN).expect("test value fits u8"),
            0x01,
            u8::try_from(DATA_RUN_CLUSTERS - 1).expect("test value fits u8"),
            0x00,
        ]
    }

    /// Builds a compressed value reader over the synthetic data run.
    ///
    /// `compression_unit_size` equals one cluster (512) so each unit reads as
    /// a full, "incompressible" cluster — the raw bytes are copied verbatim
    /// into the decompressed buffer, exercising the read/seek/position
    /// arithmetic without needing real LZNT1 input.
    fn make_value<'n>(
        ntfs: &'n Ntfs,
        run: &[u8],
        decompressed_size: u64,
        initialized_size: u64,
    ) -> NtfsCompressedNonResidentAttributeValue<'n> {
        make_value_sized(ntfs, run, CLUSTER_SIZE, decompressed_size, initialized_size)
    }

    /// Like [`make_value`] but with an explicit compression-unit size.
    fn make_value_sized<'n>(
        ntfs: &'n Ntfs,
        run: &[u8],
        compression_unit_size: u64,
        decompressed_size: u64,
        initialized_size: u64,
    ) -> NtfsCompressedNonResidentAttributeValue<'n> {
        let inner = NtfsNonResidentAttributeValue::new(
            ntfs,
            run,
            crate::types::NtfsPosition::new(0x1000),
            decompressed_size,
            initialized_size,
        )
        .expect("data run parses");
        NtfsCompressedNonResidentAttributeValue::new(
            &inner,
            compression_unit_size,
            decompressed_size,
            initialized_size,
        )
        .expect("data-run map parses")
    }

    #[test]
    fn accessors_report_genuine_geometry() {
        let mut fs = build_image(&[]);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        let value = make_value(&ntfs, &run, 1500, 1000);

        // len / is_empty come from decompressed_size (1500, not 0/1).
        assert_eq!(value.len(), 1500);
        assert!(!value.is_empty());
        assert_eq!(
            FsReadSeek::<fsmnt_testkit::Cursor<std::vec::Vec<u8>>>::len(&value),
            1500
        );

        // stream_position starts at 0 and is reported by both accessors.
        assert_eq!(value.stream_position(), 0);
        assert_eq!(
            FsReadSeek::<fsmnt_testkit::Cursor<std::vec::Vec<u8>>>::stream_position(&value),
            0
        );

        let empty = make_value(&ntfs, &run, 0, 0);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn read_returns_initialized_bytes_then_zeros() {
        // 1500-byte value, initialized to 1000. Units are 512 bytes each:
        //   unit 0 [0..512)   fully initialized
        //   unit 1 [512..1024) initialized through 1000, zero after
        //   unit 2 [1024..1500) entirely beyond initialized_size -> zeros
        let mut payload = std::vec![0u8; 1500];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("test value fits u8"); // deterministic, distinct-ish pattern
        }
        let mut fs = build_image(&payload);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        let mut value = make_value(&ntfs, &run, 1500, 1000);

        let mut out = std::vec![0xEEu8; 1500];
        let n = value.read(&mut fs, &mut out).unwrap();
        assert_eq!(n, 1500);
        assert_eq!(value.stream_position(), 1500);

        // Initialized region matches the raw payload.
        assert_eq!(&out[..1000], &payload[..1000]);
        // Bytes from initialized_size to decompressed_size read as zero.
        assert!(out[1000..1500].iter().all(|&b| b == 0));

        // The trait stream_position accessor reports the advanced offset
        // (1500), not the 0 a return-value replacement would yield.
        assert_eq!(
            FsReadSeek::<fsmnt_testkit::Cursor<std::vec::Vec<u8>>>::stream_position(&value),
            1500
        );
    }

    #[test]
    fn enforce_initialized_size_zeros_within_first_unit() {
        // decompressed_size 512 (one full unit), initialized_size 300. The
        // first unit holds real data only through offset 300; bytes 300..512
        // must read as zero. This exercises enforce_initialized_size where
        // `unit_start + cu_size` (the unit end) genuinely matters: with
        // unit_start 0, the `+` cannot be a `*` (0 * cu = 0 would skip the
        // zero-fill and leak real data).
        let payload: std::vec::Vec<u8> = (0..512u32)
            .map(|i| u8::try_from(i % 250 + 1).expect("test value fits u8"))
            .collect();
        let mut fs = build_image(&payload);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        let mut value = make_value(&ntfs, &run, 512, 300);

        let mut out = std::vec![0u8; 512];
        assert_eq!(value.read(&mut fs, &mut out).unwrap(), 512);
        assert_eq!(&out[..300], &payload[..300]);
        assert!(
            out[300..512].iter().all(|&b| b == 0),
            "bytes beyond initialized_size must be zero",
        );
    }

    #[test]
    fn read_stops_at_decompressed_size() {
        let payload = std::vec![0x5Au8; 600];
        let mut fs = build_image(&payload);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        // decompressed_size 600 sits inside the second unit.
        let mut value = make_value(&ntfs, &run, 600, 600);

        let mut out = std::vec![0u8; 1024];
        let n = value.read(&mut fs, &mut out).unwrap();
        assert_eq!(n, 600);
        assert_eq!(&out[..600], &payload[..600]);
        // A second read at EOF returns 0.
        assert_eq!(value.read(&mut fs, &mut out).unwrap(), 0);
    }

    #[test]
    fn read_into_small_buffer_advances_position() {
        let mut payload = std::vec![0u8; 700];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = u8::try_from(i % 200).expect("test value fits u8");
        }
        let mut fs = build_image(&payload);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        let mut value = make_value(&ntfs, &run, 700, 700);

        // Read 100 bytes from offset 0.
        let mut out = std::vec![0u8; 100];
        assert_eq!(value.read(&mut fs, &mut out).unwrap(), 100);
        assert_eq!(value.stream_position(), 100);
        assert_eq!(&out[..], &payload[0..100]);

        // Seek across the unit boundary to 500 and read 50 bytes spanning
        // units 0 and 1 (offset_in_unit / remaining_in_unit math).
        let pos = value.seek(&mut fs, SeekFrom::Start(500)).unwrap();
        assert_eq!(pos, 500);
        assert_eq!(value.stream_position(), 500);
        let mut out2 = std::vec![0u8; 50];
        assert_eq!(value.read(&mut fs, &mut out2).unwrap(), 50);
        assert_eq!(&out2[..], &payload[500..550]);
        assert_eq!(value.stream_position(), 550);
    }

    #[test]
    fn seek_reports_new_position_and_clamps() {
        let payload = std::vec![1u8; 800];
        let mut fs = build_image(&payload);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = data_run_bytes();
        let mut value = make_value(&ntfs, &run, 800, 800);

        assert_eq!(value.seek(&mut fs, SeekFrom::Start(300)).unwrap(), 300);
        assert_eq!(value.stream_position(), 300);
        assert_eq!(value.seek(&mut fs, SeekFrom::End(0)).unwrap(), 800);
        assert_eq!(value.seek(&mut fs, SeekFrom::Current(-100)).unwrap(), 700);
    }

    /// Builds an LZNT1 stream consisting of a single *uncompressed* chunk
    /// holding `literals`. The 2-byte chunk header is
    /// `((len-1) & 0x0FFF) | (0b011 << 12)` with the 0x8000 "compressed" bit
    /// clear, so a spec-compliant decoder copies the literals verbatim.
    #[cfg(feature = "compression")]
    fn lznt1_uncompressed_chunk(literals: &[u8]) -> std::vec::Vec<u8> {
        let header: u16 = u16::try_from((literals.len() - 1) & 0x0FFF)
            .expect("test value fits u16")
            | (0b011 << 12);
        let mut out = header.to_le_bytes().to_vec();
        out.extend_from_slice(literals);
        out
    }

    #[cfg(feature = "compression")]
    #[test]
    fn strict_mode_decompresses_partial_unit() {
        // Place a hand-built LZNT1 stream in the data run. Its length is below
        // the compression unit size, so the unit reads partially and takes the
        // decompression branch. Strict mode must reproduce the original bytes.
        let original: std::vec::Vec<u8> = (0..400u32)
            .map(|i| u8::try_from(i % 17).expect("test byte fits in u8"))
            .collect();
        let compressed = lznt1_uncompressed_chunk(&original);
        assert!(
            compressed.len() < usize::try_from(CLUSTER_SIZE).expect("test value fits usize"),
            "must be partial"
        );

        let mut fs = build_image(&compressed);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = compressed_data_run_bytes();
        let mut value = make_value_sized(
            &ntfs,
            &run,
            DATA_RUN_CLUSTERS * CLUSTER_SIZE,
            u64::try_from(original.len()).expect("test data length fits in u64"),
            u64::try_from(original.len()).expect("test data length fits in u64"),
        );

        let mut out = std::vec![0u8; original.len()];
        let n = value.read(&mut fs, &mut out).unwrap();
        assert_eq!(n, original.len());
        assert_eq!(out, original);
    }

    #[test]
    fn recovery_mode_governs_io_error_handling() {
        // The backing reader fails every read of the data run. In Strict mode
        // the error propagates; in BestEffort mode the unit is zero-filled and
        // the read succeeds. This distinguishes the `recovery_mode ==
        // BestEffort` check in the I/O-error arm.
        let payload = std::vec![0x11u8; 512];

        let strict_fs = FailingReader {
            inner: build_image(&payload),
        };
        let mut strict_fs = strict_fs;
        let ntfs = Ntfs::new(&mut strict_fs).unwrap();
        let run = data_run_bytes();
        let mut strict = make_value(&ntfs, &run, 512, 512);
        let mut out = std::vec![0u8; 512];
        assert!(
            strict.read(&mut strict_fs, &mut out).is_err(),
            "strict mode must propagate the I/O error",
        );

        let mut lenient = make_value(&ntfs, &run, 512, 512);
        lenient.set_recovery_mode(CompressionRecoveryMode::BestEffort);
        let mut out2 = std::vec![0xABu8; 512];
        let n = lenient.read(&mut strict_fs, &mut out2).unwrap();
        assert_eq!(n, 512);
        assert!(
            out2.iter().all(|&b| b == 0),
            "best-effort recovery zero-fills the unreadable unit",
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn best_effort_recovery_survives_corrupt_unit() {
        // A partial unit of bytes that are not valid LZNT1. Strict mode
        // errors; BestEffort mode recovers (zero-fills) and returns Ok. This
        // distinguishes the two recovery modes, so `set_recovery_mode` cannot
        // be replaced with a no-op.
        let garbage = std::vec![0xFFu8; 200];
        let mut fs = build_image(&garbage);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        let run = compressed_data_run_bytes();

        // Strict mode: decompressing the garbage fails.
        let mut strict = make_value_sized(&ntfs, &run, DATA_RUN_CLUSTERS * CLUSTER_SIZE, 256, 256);
        let mut out = std::vec![0u8; 256];
        assert!(strict.read(&mut fs, &mut out).is_err());

        // BestEffort mode: the same input is recovered without error.
        let mut lenient = make_value_sized(&ntfs, &run, DATA_RUN_CLUSTERS * CLUSTER_SIZE, 256, 256);
        lenient.set_recovery_mode(CompressionRecoveryMode::BestEffort);
        let mut out2 = std::vec![0u8; 256];
        assert_eq!(lenient.read(&mut fs, &mut out2).unwrap(), 256);
    }
}
