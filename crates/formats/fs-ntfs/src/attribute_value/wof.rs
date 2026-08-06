//! WOF (Windows Overlay Filter) compressed data reader.
//!
//! Reads and decompresses files compressed via WOF's file provider.
//! WOF stores compressed data in a `:WofCompressedData` alternate data
//! stream with a chunk offset table followed by concatenated compressed
//! chunks. This is separate from NTFS native compression (LZNT1) which
//! uses inline compression units within data runs.

use alloc::vec;
use alloc::vec::Vec;

use super::seek_contiguous;
use crate::attribute_value::CompressionRecoveryMode;
use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::structured_values::wof::WofAlgorithm;

/// Reader for WOF-compressed file data.
///
/// Created from the raw `:WofCompressedData` ADS bytes plus the
/// uncompressed file size and algorithm from the WOF reparse point.
/// Implements [`Read`] and [`Seek`] over the decompressed stream.
#[derive(Debug)]
pub struct NtfsWofAttributeValue {
    compressed_data: Vec<u8>,
    uncompressed_size: u64,
    algorithm: nt_compression::Algorithm,
    chunk_size: u32,
    chunk_offsets: Vec<u64>,
    table_end: usize,
    stream_position: u64,
    decompressed_buffer: Vec<u8>,
    buffered_chunk_index: Option<usize>,
    recovery_mode: CompressionRecoveryMode,
}

impl NtfsWofAttributeValue {
    /// Create a new WOF reader from raw `:WofCompressedData` ADS bytes.
    ///
    /// `uncompressed_size` and `algorithm` come from the WOF reparse
    /// point metadata ([`WofInfo`]).
    ///
    /// [`WofInfo`]: crate::structured_values::wof::WofInfo
    ///
    /// # Errors
    ///
    /// Returns an error if the WOF chunk table or compressed payload is inconsistent with the declared size.
    pub fn new(
        compressed_data: Vec<u8>,
        uncompressed_size: u64,
        algorithm: WofAlgorithm,
        recovery_mode: CompressionRecoveryMode,
    ) -> Result<Self> {
        let chunk_size = algorithm.chunk_size();
        let num_chunks = uncompressed_size
            .checked_add(u64::from(chunk_size) - 1)
            .map_or(0, |n| n / u64::from(chunk_size));

        if uncompressed_size == 0 {
            return Ok(Self {
                compressed_data,
                uncompressed_size: 0,
                algorithm: algorithm.to_nt_algorithm(),
                chunk_size,
                chunk_offsets: Vec::new(),
                table_end: 0,
                stream_position: 0,
                decompressed_buffer: Vec::new(),
                buffered_chunk_index: None,
                recovery_mode,
            });
        }

        let entry_size: usize = if uncompressed_size < 0x1_0000_0000 {
            4
        } else {
            8
        };
        let table_entries =
            usize::try_from(num_chunks - 1).map_err(|_| NtfsError::InvalidWofData {
                reason: "chunk count exceeds addressable memory",
            })?;
        let table_end = table_entries
            .checked_mul(entry_size)
            .ok_or(NtfsError::InvalidWofData {
                reason: "chunk offset table size overflow",
            })?;

        if compressed_data.len() < table_end {
            return Err(NtfsError::InvalidWofData {
                reason: "ADS too small for chunk offset table",
            });
        }

        let chunk_offsets = parse_chunk_offsets(&compressed_data, table_entries, entry_size)?;

        validate_chunk_offsets(&chunk_offsets, compressed_data.len() - table_end)?;

        Ok(Self {
            compressed_data,
            uncompressed_size,
            algorithm: algorithm.to_nt_algorithm(),
            chunk_size,
            chunk_offsets,
            table_end,
            stream_position: 0,
            decompressed_buffer: vec![
                0u8;
                usize::try_from(chunk_size).map_err(|_| {
                    NtfsError::InvalidWofData {
                        reason: "chunk size exceeds addressable memory",
                    }
                })?
            ],
            buffered_chunk_index: None,
            recovery_mode,
        })
    }

    /// Sets the compression error recovery mode.
    pub fn set_recovery_mode(&mut self, mode: CompressionRecoveryMode) {
        self.recovery_mode = mode;
    }

    /// Returns the total uncompressed file size in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.uncompressed_size
    }

    /// Returns `true` if the uncompressed file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.uncompressed_size == 0
    }

    /// Returns the current position in the decompressed stream.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn decompressed_chunk_size(&self, chunk_index: usize) -> usize {
        let num_chunks = self.chunk_offsets.len();
        if chunk_index + 1 < num_chunks {
            usize::try_from(self.chunk_size).expect("a WOF chunk size fits usize")
        } else {
            let remainder = self.uncompressed_size % u64::from(self.chunk_size);
            if remainder == 0 {
                usize::try_from(self.chunk_size).expect("a WOF chunk size fits usize")
            } else {
                usize::try_from(remainder)
                    .expect("a WOF chunk remainder is bounded by its u32 chunk size")
            }
        }
    }

    fn ensure_chunk_buffered(&mut self, chunk_index: usize) -> Result<()> {
        if self.buffered_chunk_index == Some(chunk_index) {
            return Ok(());
        }

        let decompressed_size = self.decompressed_chunk_size(chunk_index);
        let compressed_range = self.chunk_compressed_range(chunk_index);
        let compressed_size = compressed_range.len();

        self.decompressed_buffer.resize(decompressed_size, 0);

        if compressed_size >= decompressed_size {
            self.decompressed_buffer[..decompressed_size].copy_from_slice(
                &self.compressed_data
                    [compressed_range.start..compressed_range.start + decompressed_size],
            );
        } else {
            self.decompressed_buffer[..decompressed_size].fill(0);
            let algo = self.algorithm;
            let mode = self.recovery_mode;
            let out = &mut self.decompressed_buffer[..decompressed_size];
            let input = &self.compressed_data[compressed_range];
            match mode {
                CompressionRecoveryMode::Strict => {
                    nt_compression::decompress(algo, input, out)
                        .map(|_| ())
                        .map_err(|e| NtfsError::DecompressionError {
                            message: alloc::format!("{e}"),
                        })?;
                }
                CompressionRecoveryMode::BestEffort => {
                    nt_compression::decompress_lenient(algo, input, out);
                }
            }
        }

        self.buffered_chunk_index = Some(chunk_index);
        Ok(())
    }

    fn chunk_compressed_range(&self, chunk_index: usize) -> core::ops::Range<usize> {
        let start = self.chunk_offsets[chunk_index];
        let end = if chunk_index + 1 < self.chunk_offsets.len() {
            self.chunk_offsets[chunk_index + 1]
        } else {
            u64::try_from(self.compressed_data.len() - self.table_end)
                .expect("a slice length fits u64")
        };
        let abs_start = self.table_end
            + usize::try_from(start).expect("validated chunk offsets fit addressable memory");
        let abs_end = self.table_end
            + usize::try_from(end).expect("validated chunk offsets fit addressable memory");
        abs_start..abs_end
    }
}

impl Read for NtfsWofAttributeValue {
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        if self.stream_position >= self.uncompressed_size {
            return Ok(0);
        }

        let mut bytes_read = 0;

        while bytes_read < buf.len() && self.stream_position < self.uncompressed_size {
            let chunk_index = usize::try_from(self.stream_position / u64::from(self.chunk_size))
                .map_err(|_| {
                    crate::io::Error::from(NtfsError::InvalidWofData {
                        reason: "chunk index exceeds addressable memory",
                    })
                })?;

            self.ensure_chunk_buffered(chunk_index)
                .map_err(crate::io::Error::from)?;

            let offset_in_chunk =
                usize::try_from(self.stream_position % u64::from(self.chunk_size))
                    .expect("a chunk-relative offset is bounded by its u32 chunk size");
            let chunk_decompressed = self.decompressed_chunk_size(chunk_index);
            let remaining_in_chunk = chunk_decompressed - offset_in_chunk;
            let remaining_in_file = usize::try_from(self.uncompressed_size - self.stream_position)
                .unwrap_or(usize::MAX);
            let remaining_in_buf = buf.len() - bytes_read;

            let to_copy = remaining_in_chunk
                .min(remaining_in_file)
                .min(remaining_in_buf);

            buf[bytes_read..bytes_read + to_copy].copy_from_slice(
                &self.decompressed_buffer[offset_in_chunk..offset_in_chunk + to_copy],
            );

            bytes_read += to_copy;
            self.stream_position += u64::try_from(to_copy).expect("a copied slice length fits u64");
        }

        Ok(bytes_read)
    }
}

impl Seek for NtfsWofAttributeValue {
    fn seek(&mut self, pos: SeekFrom) -> crate::io::Result<u64> {
        seek_contiguous(&mut self.stream_position, self.uncompressed_size, pos)
            .map_err(crate::io::Error::from)
    }
}

fn parse_chunk_offsets(data: &[u8], table_entries: usize, entry_size: usize) -> Result<Vec<u64>> {
    let mut offsets = Vec::with_capacity(table_entries + 1);
    offsets.push(0u64);

    for i in 0..table_entries {
        let pos = i * entry_size;
        let offset = if entry_size == 4 {
            let bytes: [u8; 4] =
                data[pos..pos + 4]
                    .try_into()
                    .map_err(|_| NtfsError::InvalidWofData {
                        reason: "failed to read u32 chunk offset",
                    })?;
            u64::from(u32::from_le_bytes(bytes))
        } else {
            let bytes: [u8; 8] =
                data[pos..pos + 8]
                    .try_into()
                    .map_err(|_| NtfsError::InvalidWofData {
                        reason: "failed to read u64 chunk offset",
                    })?;
            u64::from_le_bytes(bytes)
        };
        offsets.push(offset);
    }

    Ok(offsets)
}

fn validate_chunk_offsets(offsets: &[u64], data_region_size: usize) -> Result<()> {
    for window in offsets.windows(2) {
        if window[1] < window[0] {
            return Err(NtfsError::InvalidWofData {
                reason: "chunk offsets are not monotonically increasing",
            });
        }
    }

    let data_region_size =
        u64::try_from(data_region_size).map_err(|_| NtfsError::InvalidWofData {
            reason: "ADS data region size does not fit in u64",
        })?;
    if let Some(&last) = offsets.last()
        && last > data_region_size
    {
        return Err(NtfsError::InvalidWofData {
            reason: "chunk offset exceeds ADS data bounds",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ads_with_raw_chunks(
        chunk_size: u32,
        chunks: &[&[u8]],
        uncompressed_size: u64,
    ) -> Vec<u8> {
        let num_chunks = chunks.len();
        let table_entries = if num_chunks > 0 { num_chunks - 1 } else { 0 };
        let use_u32 = uncompressed_size < 0x1_0000_0000;
        let entry_size = if use_u32 { 4 } else { 8 };

        let mut ads = vec![0u8; table_entries * entry_size];
        let mut running_offset = chunks.first().map_or(0, |c| c.len());

        for i in 0..table_entries {
            let offset = u64::try_from(running_offset).expect("test offset fits in u64");
            if use_u32 {
                ads[i * 4..(i + 1) * 4].copy_from_slice(
                    &u32::try_from(offset)
                        .expect("test value fits u32")
                        .to_le_bytes(),
                );
            } else {
                ads[i * 8..(i + 1) * 8].copy_from_slice(&offset.to_le_bytes());
            }
            if i + 1 < table_entries {
                running_offset += chunks[i + 1].len();
            }
        }

        for chunk in chunks {
            ads.extend_from_slice(chunk);
        }

        let _ = chunk_size;
        ads
    }

    #[test]
    fn parse_chunk_offset_table_u32() {
        let chunk0 = [0xAAu8; 100];
        let chunk1 = [0xBBu8; 200];
        let chunk2 = [0xCCu8; 50];
        let ads = build_ads_with_raw_chunks(4096, &[&chunk0, &chunk1, &chunk2], 4096 * 3);

        let reader = NtfsWofAttributeValue::new(
            ads,
            4096 * 3,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid parse");

        assert_eq!(reader.chunk_offsets.len(), 3);
        assert_eq!(reader.chunk_offsets[0], 0);
        assert_eq!(reader.chunk_offsets[1], 100);
        assert_eq!(reader.chunk_offsets[2], 300);
    }

    #[test]
    fn monotonic_offset_validation() {
        let mut ads = vec![0u8; 8];
        ads[0..4].copy_from_slice(&100u32.to_le_bytes());
        ads[4..8].copy_from_slice(&50u32.to_le_bytes());
        ads.extend_from_slice(&[0u8; 200]);

        let err = NtfsWofAttributeValue::new(
            ads,
            4096 * 3,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect_err("should fail");

        let msg = alloc::format!("{err}");
        assert!(
            msg.contains("not monotonically increasing"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn single_chunk_raw_passthrough() {
        let original = b"Hello, WOF world! This is uncompressed.";
        let chunk_size = 4096u32;
        let uncompressed_size =
            u64::try_from(original.len()).expect("test data length fits in u64");

        let mut padded = original.to_vec();
        padded.resize(
            usize::try_from(chunk_size).expect("test chunk size fits in usize"),
            0xDD,
        );

        let ads = build_ads_with_raw_chunks(chunk_size, &[&padded], uncompressed_size);

        let mut reader = NtfsWofAttributeValue::new(
            ads,
            uncompressed_size,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        let mut buf = vec![0u8; original.len()];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, original.len());
        assert_eq!(&buf, original);
    }

    /// Build an XPRESS stream that decompresses to `size` bytes of `byte`.
    ///
    /// Emits one literal then a match of offset=1, length=size-1 to
    /// replicate it. Handles the XPRESS length encoding (nibble sharing,
    /// byte extension, u16 extension).
    fn build_xpress_constant_stream(byte: u8, size: usize) -> Vec<u8> {
        assert!(size >= 4, "need at least 4 bytes for this helper");

        let mut payload = Vec::new();
        // XPRESS flags are processed MSB-first: bit index i checks
        // (flags >> (31 - i)) & 1. Item 0 = literal, item 1 = match,
        // so we need bit 30 set.
        let flags: u32 = 1 << 30;

        payload.push(byte);

        let length = size - 1;
        let base = length - 3;
        let field_val = u16::try_from(base.min(7)).expect("test value fits u16");
        let word: u16 = field_val & 0x7;
        payload.extend_from_slice(&word.to_le_bytes());

        if base >= 7 {
            let rem = base - 7;
            let nibble = u8::try_from(rem.min(15)).expect("test value fits u8");
            payload.push(nibble);

            if rem >= 15 {
                let byte_rem = rem - 15;
                let byte_val = u8::try_from(byte_rem.min(255)).expect("test value fits u8");
                payload.push(byte_val);

                if byte_rem >= 255 {
                    // u16 extension encodes match_length - 3.
                    let u16_val = u16::try_from(length - 3).expect("test value fits u16");
                    payload.extend_from_slice(&u16_val.to_le_bytes());
                }
            }
        }

        let mut stream = Vec::new();
        stream.extend_from_slice(&flags.to_le_bytes());
        stream.extend_from_slice(&payload);
        stream
    }

    #[test]
    fn single_chunk_decompress() {
        let compressed = build_xpress_constant_stream(0xAB, 4096);
        assert!(compressed.len() < 4096, "stream should be smaller");

        let ads = build_ads_with_raw_chunks(4096, &[&compressed], 4096);
        let mut reader = NtfsWofAttributeValue::new(
            ads,
            4096,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        let mut buf = vec![0u8; 4096];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 4096);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn multi_chunk_read() {
        let chunk0_data = vec![0x11u8; 4096];
        let chunk1_data = vec![0x22u8; 4096];
        let uncompressed_size = 8192u64;

        let ads = build_ads_with_raw_chunks(4096, &[&chunk0_data, &chunk1_data], uncompressed_size);

        let mut reader = NtfsWofAttributeValue::new(
            ads,
            uncompressed_size,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        let mut buf = vec![0u8; 8192];
        let mut total = 0;
        while total < 8192 {
            let n = reader.read(&mut buf[total..]).expect("read ok");
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(total, 8192);
        assert!(buf[..4096].iter().all(|&b| b == 0x11));
        assert!(buf[4096..].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn seek_to_position() {
        let chunk0_data = vec![0x11u8; 4096];
        let chunk1_data = vec![0x22u8; 4096];
        let uncompressed_size = 8192u64;

        let ads = build_ads_with_raw_chunks(4096, &[&chunk0_data, &chunk1_data], uncompressed_size);

        let mut reader = NtfsWofAttributeValue::new(
            ads,
            uncompressed_size,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        reader.seek(SeekFrom::Start(4096)).expect("seek ok");
        assert_eq!(reader.stream_position(), 4096);

        let mut buf = [0u8; 4];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 4);
        assert_eq!(buf, [0x22, 0x22, 0x22, 0x22]);

        reader.seek(SeekFrom::Start(0)).expect("seek ok");
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 4);
        assert_eq!(buf, [0x11, 0x11, 0x11, 0x11]);

        reader.seek(SeekFrom::End(-4)).expect("seek ok");
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 4);
        assert_eq!(buf, [0x22, 0x22, 0x22, 0x22]);
    }

    #[test]
    fn recovery_mode_zero_fills_corrupt_chunk() {
        let garbage = vec![0xFF; 100];
        let ads = build_ads_with_raw_chunks(4096, &[&garbage], 4096);

        let mut reader = NtfsWofAttributeValue::new(
            ads,
            4096,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::BestEffort,
        )
        .expect("valid");

        let mut buf = vec![0xCCu8; 4096];
        let n = reader.read(&mut buf).expect("read ok in recovery");
        assert_eq!(n, 4096);
        assert!(
            buf.iter().all(|&b| b == 0),
            "corrupt chunk should be zero-filled",
        );
    }

    #[test]
    fn empty_file() {
        let reader = NtfsWofAttributeValue::new(
            Vec::new(),
            0,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        assert!(reader.is_empty());
        assert_eq!(reader.len(), 0);
    }

    /// A two-chunk reader whose final chunk is a partial (non-aligned)
    /// remainder, with both chunks stored raw (passthrough). chunk0 is
    /// 4096 bytes of 0x11, chunk1 is 100 bytes of 0x22, `uncompressed_size`
    /// 4196. Exercises the last-chunk remainder logic and chunk ranges.
    fn partial_last_chunk_reader() -> NtfsWofAttributeValue {
        let chunk0 = vec![0x11u8; 4096];
        let chunk1 = vec![0x22u8; 100];
        let ads = build_ads_with_raw_chunks(4096, &[&chunk0, &chunk1], 4196);
        NtfsWofAttributeValue::new(
            ads,
            4196,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid")
    }

    #[test]
    fn len_and_is_empty_report_size() {
        let reader = partial_last_chunk_reader();
        assert_eq!(reader.len(), 4196);
        assert!(!reader.is_empty());
    }

    #[test]
    fn decompressed_chunk_size_full_then_remainder() {
        let reader = partial_last_chunk_reader();
        // First (non-final) chunk is a full chunk.
        assert_eq!(reader.decompressed_chunk_size(0), 4096);
        // Final chunk is the 100-byte remainder (4196 % 4096).
        assert_eq!(reader.decompressed_chunk_size(1), 100);
    }

    #[test]
    fn decompressed_chunk_size_exact_multiple_uses_full_chunk() {
        // uncompressed_size is an exact multiple of chunk_size, so the last
        // chunk is a full chunk (remainder == 0 branch).
        let chunk0 = vec![0x11u8; 4096];
        let chunk1 = vec![0x22u8; 4096];
        let ads = build_ads_with_raw_chunks(4096, &[&chunk0, &chunk1], 8192);
        let reader = NtfsWofAttributeValue::new(
            ads,
            8192,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");
        assert_eq!(reader.decompressed_chunk_size(1), 4096);
    }

    #[test]
    fn chunk_compressed_range_matches_table() {
        let reader = partial_last_chunk_reader();
        // table_end = 1 entry * 4 bytes = 4. chunk0 occupies [4, 4100).
        let r0 = reader.chunk_compressed_range(0);
        assert_eq!(r0.start, 4);
        assert_eq!(r0.len(), 4096);
        // chunk1 (last) occupies [4100, 4200): end = data.len() - table_end.
        let r1 = reader.chunk_compressed_range(1);
        assert_eq!(r1.start, 4100);
        assert_eq!(r1.len(), 100);
    }

    #[test]
    fn full_read_spans_both_chunks_with_partial_tail() {
        let mut reader = partial_last_chunk_reader();
        let mut buf = vec![0u8; 4196];
        let mut total = 0;
        while total < 4196 {
            let n = reader.read(&mut buf[total..]).expect("read ok");
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(total, 4196);
        assert!(buf[..4096].iter().all(|&b| b == 0x11));
        assert!(buf[4096..4196].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn single_call_read_across_chunk_boundary() {
        // A single read() call larger than chunk0 forces the while loop to
        // iterate across the chunk boundary, exercising remaining_in_buf
        // and offset_in_chunk updates.
        let mut reader = partial_last_chunk_reader();
        let mut buf = vec![0u8; 4150];
        let n = reader.read(&mut buf).expect("read ok");
        // First call returns at most through chunk0 plus part of chunk1.
        assert!(n >= 4096, "expected to read past chunk0, got {n}");
        assert!(buf[..4096].iter().all(|&b| b == 0x11));
        assert!(buf[4096..n].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn read_mid_chunk_after_seek() {
        // Seek into the middle of chunk0 then read into a buffer large
        // enough to span both chunks. The chunk0 tail is bounded by
        // remaining_in_chunk = chunk_decompressed(4096) - offset(50) = 4046,
        // so exactly 4046 bytes of 0x11 then 100 bytes of 0x22 are returned
        // across the two loop iterations.
        let mut reader = partial_last_chunk_reader();
        reader.seek(SeekFrom::Start(50)).expect("seek ok");
        let mut buf = vec![0u8; 5000];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 4146, "4046 from chunk0 tail + 100 from chunk1");
        assert!(buf[..4046].iter().all(|&b| b == 0x11));
        assert!(buf[4046..4146].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn read_near_file_end_in_partial_chunk() {
        // Seek into the partial last chunk near EOF; remaining_in_file
        // bounds the copy.
        let mut reader = partial_last_chunk_reader();
        reader.seek(SeekFrom::Start(4196 - 30)).expect("seek ok");
        let mut buf = vec![0u8; 100];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 30, "only 30 bytes remain in the file");
        assert!(buf[..30].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn set_recovery_mode_switches_behavior() {
        // Build a chunk that is not valid compressed data and is smaller
        // than the decompressed size so the decompression path runs.
        let garbage = vec![0xFFu8; 100];
        let ads = build_ads_with_raw_chunks(4096, &[&garbage], 4096);
        let mut reader = NtfsWofAttributeValue::new(
            ads,
            4096,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        // Strict mode: a corrupt chunk fails the read.
        let mut buf = vec![0u8; 4096];
        assert!(reader.read(&mut buf).is_err(), "strict mode should error");

        // Switching to BestEffort makes the same chunk zero-fill instead.
        reader.set_recovery_mode(CompressionRecoveryMode::BestEffort);
        let n = reader.read(&mut buf).expect("best-effort read ok");
        assert_eq!(n, 4096);
        assert!(buf.iter().all(|&b| b == 0), "corrupt chunk zero-filled");
    }

    #[test]
    fn parse_chunk_offsets_u64_entries() {
        // Two u64 entries -> offsets = [0, first, second]. Exercises the
        // 8-byte branch and the `pos + 8` slice arithmetic.
        let mut data = Vec::new();
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&250u64.to_le_bytes());
        let offsets = parse_chunk_offsets(&data, 2, 8).expect("parse ok");
        assert_eq!(offsets, vec![0, 100, 250]);
    }

    #[test]
    fn parse_chunk_offsets_u32_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&250u32.to_le_bytes());
        let offsets = parse_chunk_offsets(&data, 2, 4).expect("parse ok");
        assert_eq!(offsets, vec![0, 100, 250]);
    }

    #[test]
    fn validate_chunk_offsets_accepts_equal_adjacent() {
        // Equal adjacent offsets (an empty chunk) are valid: the check is
        // strictly "decreasing", not "non-increasing".
        validate_chunk_offsets(&[0, 5, 5], 100).expect("equal offsets are valid");
    }

    #[test]
    fn validate_chunk_offsets_rejects_decreasing() {
        let err = validate_chunk_offsets(&[0, 10, 5], 100).expect_err("must reject");
        assert!(alloc::format!("{err}").contains("monotonically increasing"));
    }

    #[test]
    fn validate_chunk_offsets_last_equals_region_is_valid() {
        // last offset == data_region_size is in-bounds (the `>` is strict).
        validate_chunk_offsets(&[0, 5, 10], 10).expect("last == region is valid");
    }

    #[test]
    fn validate_chunk_offsets_last_exceeds_region_rejected() {
        let err = validate_chunk_offsets(&[0, 5, 11], 10).expect_err("must reject");
        assert!(alloc::format!("{err}").contains("exceeds ADS data bounds"));
    }

    #[test]
    fn read_past_end_returns_zero() {
        let chunk_data = vec![0xAAu8; 4096];
        let ads = build_ads_with_raw_chunks(4096, &[&chunk_data], 100);

        let mut reader = NtfsWofAttributeValue::new(
            ads,
            100,
            WofAlgorithm::Xpress4K,
            CompressionRecoveryMode::Strict,
        )
        .expect("valid");

        let mut buf = vec![0u8; 200];
        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 100);

        let n = reader.read(&mut buf).expect("read ok");
        assert_eq!(n, 0);
    }
}
