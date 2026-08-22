//! Owned, stateless positioned access to an NTFS attribute value.

use alloc::boxed::Box;
#[cfg(feature = "compression")]
use alloc::vec::Vec;
use fsmnt_parser_core::error::IoError;

#[cfg(feature = "compression")]
use super::compressed::CompressionRecoveryMode;
use crate::data_run_map::DataRunMap;
#[cfg(feature = "compression")]
use crate::error::NtfsError;
use crate::error::Result;
use crate::io::{Read, Seek};

/// An attribute value detached from the file record that described it.
///
/// Resident values retain only their value bytes. Non-resident values retain
/// a compact map of their data runs, allowing each positioned read to locate
/// its first run by binary search instead of replaying the run iterator from
/// the beginning. The type has no borrow from an [`NtfsFile`](crate::NtfsFile)
/// and can therefore be cached independently of the parsed MFT record.
#[derive(Clone, Debug)]
pub struct NtfsAttributeValueOwned {
    data: OwnedValueData,
    data_size: u64,
    initialized_size: u64,
}

#[derive(Clone, Debug)]
enum OwnedValueData {
    Resident(Box<[u8]>),
    NonResident(DataRunMap),
    #[cfg(feature = "compression")]
    Compressed(OwnedCompressedValue),
}

/// Reusable state for positioned reads from a native LZNT1-compressed value.
#[cfg(feature = "compression")]
#[derive(Clone, Debug)]
struct OwnedCompressedValue {
    map: DataRunMap,
    compression_unit_size: u64,
    recovery_mode: CompressionRecoveryMode,
    compressed_buffer: Vec<u8>,
    decompressed_buffer: Vec<u8>,
    buffered_unit: Option<u64>,
}

#[cfg(feature = "compression")]
impl OwnedCompressedValue {
    fn enforce_initialized_size(&mut self, unit_index: u64, initialized_size: u64) {
        let unit_start = unit_index.saturating_mul(self.compression_unit_size);
        let zero_from =
            usize::try_from(initialized_size.saturating_sub(unit_start)).unwrap_or(usize::MAX);
        if zero_from < self.decompressed_buffer.len() {
            self.decompressed_buffer[zero_from..].fill(0);
        }
    }

    fn ensure_unit_buffered<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        position: u64,
        initialized_size: u64,
    ) -> Result<()> {
        let unit_index = position / self.compression_unit_size;
        if self.buffered_unit == Some(unit_index) {
            return Ok(());
        }

        let unit_offset = unit_index
            .checked_mul(self.compression_unit_size)
            .ok_or(NtfsError::from(IoError::invalid_input()))?;
        let allocated =
            match self
                .map
                .read_allocated_prefix_at(fs, unit_offset, &mut self.compressed_buffer)
            {
                Ok(allocated) => allocated,
                Err(_) if self.recovery_mode == CompressionRecoveryMode::BestEffort => {
                    self.decompressed_buffer.fill(0);
                    self.enforce_initialized_size(unit_index, initialized_size);
                    self.buffered_unit = Some(unit_index);
                    return Ok(());
                }
                Err(error) => return Err(error),
            };

        if allocated == 0 {
            self.decompressed_buffer.fill(0);
        } else if allocated == self.compressed_buffer.len() {
            self.decompressed_buffer
                .copy_from_slice(&self.compressed_buffer);
        } else {
            self.decompressed_buffer.fill(0);
            match self.recovery_mode {
                CompressionRecoveryMode::Strict => {
                    nt_compression::lznt1::decompress(
                        &self.compressed_buffer[..allocated],
                        &mut self.decompressed_buffer,
                    )
                    .map_err(|error| NtfsError::DecompressionError {
                        message: alloc::format!("{error}"),
                    })?;
                }
                CompressionRecoveryMode::BestEffort => {
                    crate::compression_recovery::decompress_lznt1_lenient(
                        &self.compressed_buffer[..allocated],
                        &mut self.decompressed_buffer,
                    );
                }
            }
        }

        self.enforce_initialized_size(unit_index, initialized_size);
        self.buffered_unit = Some(unit_index);
        Ok(())
    }

    fn read_at<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        offset: u64,
        initialized_size: u64,
        destination: &mut [u8],
    ) -> Result<()> {
        let mut copied = 0usize;
        while copied < destination.len() {
            let position = offset
                .checked_add(u64::try_from(copied).expect("a slice length fits u64"))
                .ok_or(NtfsError::from(IoError::invalid_input()))?;
            self.ensure_unit_buffered(fs, position, initialized_size)?;

            let offset_in_unit = usize::try_from(position % self.compression_unit_size)
                .expect("a compression-unit offset fits usize");
            let to_copy =
                (destination.len() - copied).min(self.decompressed_buffer.len() - offset_in_unit);
            destination[copied..copied + to_copy].copy_from_slice(
                &self.decompressed_buffer[offset_in_unit..offset_in_unit + to_copy],
            );
            copied += to_copy;
        }
        Ok(())
    }
}

impl NtfsAttributeValueOwned {
    pub(super) fn resident(data: &[u8]) -> Self {
        let data = Box::<[u8]>::from(data);
        let data_size = u64::try_from(data.len()).expect("a slice length fits u64");
        Self {
            data: OwnedValueData::Resident(data),
            data_size,
            initialized_size: data_size,
        }
    }

    pub(super) fn non_resident(map: DataRunMap, data_size: u64, initialized_size: u64) -> Self {
        Self {
            data: OwnedValueData::NonResident(map),
            data_size,
            initialized_size: initialized_size.min(data_size),
        }
    }

    #[cfg(feature = "compression")]
    pub(super) fn compressed(
        map: DataRunMap,
        compression_unit_size: u64,
        data_size: u64,
        initialized_size: u64,
        recovery_mode: CompressionRecoveryMode,
        compressed_buffer: Vec<u8>,
        decompressed_buffer: Vec<u8>,
    ) -> Self {
        Self {
            data: OwnedValueData::Compressed(OwnedCompressedValue {
                map,
                compression_unit_size,
                recovery_mode,
                compressed_buffer,
                decompressed_buffer,
                buffered_unit: None,
            }),
            data_size,
            initialized_size: initialized_size.min(data_size),
        }
    }

    /// Returns the logical length of the attribute value in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.data_size
    }

    /// Returns whether this attribute value contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data_size == 0
    }

    /// Reads bytes at `offset` without rebuilding sequential stream state.
    ///
    /// Reads are capped at the logical end of the value. Sparse runs and the
    /// uninitialized tail of a non-resident value are returned as zeroes.
    /// Native compressed values retain their most recently decoded compression
    /// unit, so nearby calls can reuse the same allocation and device read.
    ///
    /// # Errors
    ///
    /// Returns an error if a mapped disk range cannot be sought or read, or
    /// if malformed data runs do not cover the requested initialized range.
    pub fn read_at<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if buffer.is_empty() || offset >= self.data_size {
            return Ok(0);
        }

        let available = self.data_size - offset;
        let to_read = buffer
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let destination = &mut buffer[..to_read];

        match &mut self.data {
            OwnedValueData::Resident(data) => {
                let start = usize::try_from(offset).map_err(|_| IoError::invalid_input())?;
                destination.copy_from_slice(&data[start..start + to_read]);
            }
            OwnedValueData::NonResident(map) => {
                let initialized = self.initialized_size.saturating_sub(offset);
                let initialized = to_read.min(usize::try_from(initialized).unwrap_or(usize::MAX));
                if initialized != 0 {
                    map.read_at(fs, offset, &mut destination[..initialized])?;
                }
                destination[initialized..].fill(0);
            }
            #[cfg(feature = "compression")]
            OwnedValueData::Compressed(value) => {
                value.read_at(fs, offset, self.initialized_size, destination)?;
            }
        }

        Ok(to_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "compression")]
    use fsmnt_testkit::CountingReader;
    use fsmnt_testkit::Cursor;

    #[test]
    fn resident_reads_are_bounded_without_a_backing_reader() {
        let mut value = NtfsAttributeValueOwned::resident(b"resident");
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut output = [0_u8; 8];

        assert_eq!(value.read_at(&mut reader, 3, &mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"ident");
        assert_eq!(value.read_at(&mut reader, 8, &mut output).unwrap(), 0);
    }

    #[test]
    fn non_resident_reads_cross_physical_and_sparse_runs() {
        let map = DataRunMap::from_segments_for_test(&[(Some(4), 3), (None, 2), (Some(12), 4)]);
        let mut value = NtfsAttributeValueOwned::non_resident(map, 9, 8);
        let mut disk = Cursor::new(b"xxxxABCyyyyyWXYZ".to_vec());
        let mut output = [0xFF_u8; 9];

        assert_eq!(value.read_at(&mut disk, 0, &mut output).unwrap(), 9);
        assert_eq!(&output, b"ABC\0\0WXY\0");
    }

    #[test]
    fn uninitialized_ranges_do_not_touch_the_backing_reader() {
        let map = DataRunMap::from_segments_for_test(&[(Some(100), 4)]);
        let mut value = NtfsAttributeValueOwned::non_resident(map, 4, 0);
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut output = [0xFF_u8; 4];

        assert_eq!(value.read_at(&mut empty, 0, &mut output).unwrap(), 4);
        assert_eq!(output, [0; 4]);
    }

    #[cfg(feature = "compression")]
    fn lznt1_uncompressed_chunk(literals: &[u8]) -> Vec<u8> {
        let header = u16::try_from((literals.len() - 1) & 0x0FFF)
            .expect("the test chunk length fits u16")
            | (0b011 << 12);
        let mut encoded = header.to_le_bytes().to_vec();
        encoded.extend_from_slice(literals);
        encoded
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compressed_reads_reuse_the_buffered_unit_without_io() {
        const UNIT_SIZE: usize = 4096;
        const DISK_OFFSET: usize = 128;

        let original: Vec<u8> = (0..400_u16)
            .map(|value| u8::try_from(value % 29).expect("the test byte fits u8"))
            .collect();
        let encoded = lznt1_uncompressed_chunk(&original);
        let allocated_size = 512_u64;
        let mut disk = vec![0_u8; DISK_OFFSET + usize::try_from(allocated_size).unwrap()];
        disk[DISK_OFFSET..DISK_OFFSET + encoded.len()].copy_from_slice(&encoded);

        let map = DataRunMap::from_segments_for_test(&[
            (Some(u64::try_from(DISK_OFFSET).unwrap()), allocated_size),
            (None, u64::try_from(UNIT_SIZE).unwrap() - allocated_size),
        ]);
        let mut value = NtfsAttributeValueOwned::compressed(
            map,
            u64::try_from(UNIT_SIZE).unwrap(),
            u64::try_from(original.len()).unwrap(),
            u64::try_from(original.len()).unwrap(),
            CompressionRecoveryMode::Strict,
            vec![0; UNIT_SIZE],
            vec![0; UNIT_SIZE],
        );
        let mut reader = CountingReader::new(Cursor::new(disk));

        let mut first = [0_u8; 32];
        assert_eq!(value.read_at(&mut reader, 17, &mut first).unwrap(), 32);
        assert_eq!(&first, &original[17..49]);

        reader.reset_stats();
        let mut second = [0_u8; 40];
        assert_eq!(value.read_at(&mut reader, 211, &mut second).unwrap(), 40);
        assert_eq!(&second, &original[211..251]);
        assert_eq!(reader.stats().read_calls(), 0);
        assert_eq!(reader.stats().seek_calls(), 0);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn sparse_compression_unit_reads_as_zero_without_io() {
        const UNIT_SIZE: usize = 4096;
        let unit_size = u64::try_from(UNIT_SIZE).unwrap();
        let map = DataRunMap::from_segments_for_test(&[(None, unit_size)]);
        let mut value = NtfsAttributeValueOwned::compressed(
            map,
            unit_size,
            128,
            128,
            CompressionRecoveryMode::Strict,
            vec![0; UNIT_SIZE],
            vec![0; UNIT_SIZE],
        );
        let mut reader = CountingReader::new(Cursor::new(Vec::<u8>::new()));
        let mut output = [0xFF_u8; 128];

        assert_eq!(value.read_at(&mut reader, 0, &mut output).unwrap(), 128);
        assert_eq!(output, [0; 128]);
        assert_eq!(reader.stats().read_calls(), 0);
        assert_eq!(reader.stats().seek_calls(), 0);
    }
}
