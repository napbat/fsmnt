//! File-extent assembly, sparse ranges, and transparent decompression.

use alloc::vec::Vec;

use crate::item::{Compression, EXTENT_DATA_KEY, ExtentKind, FileExtent};
use crate::{Btrfs, BtrfsEntry, BtrfsError, DiskKey, Result};
use fsmnt_parser_core::io::{Read, Seek};

impl<R: Read + Seek> Btrfs<R> {
    /// Read all bytes of a regular file or symbolic-link target.
    ///
    /// Sparse and preallocated ranges are returned as zeroes. With the `std`
    /// feature enabled, zlib, LZO, and Zstandard extents are decompressed
    /// transparently.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotAFile`] for other inode kinds, or a checked
    /// allocation, tree, mapping, encoding, decompression, or I/O error.
    pub fn read_file(&mut self, entry: BtrfsEntry) -> Result<Vec<u8>> {
        let inode = self.inode(entry)?;
        if !inode.file_type().has_file_data() {
            return Err(BtrfsError::NotAFile);
        }
        let file_size = usize::try_from(inode.size())
            .map_err(|_| BtrfsError::FileTooLarge { size: inode.size() })?;
        let mut output = zeroed_buffer(file_size, inode.size())?;
        if output.is_empty() {
            return Ok(output);
        }

        let root = self.lookup_tree_root(entry.tree_id())?;
        let items = self.collect_items(
            root,
            DiskKey::range_start(entry.object_id(), EXTENT_DATA_KEY),
            DiskKey::range_end(entry.object_id(), EXTENT_DATA_KEY),
        )?;
        let verify_checksums = inode.has_data_checksums();
        let sector_size = self.superblock().sector_size();
        let mut previous_end = None;
        for item in items {
            let extent = FileExtent::parse(item.key, &item.data, sector_size)?;
            if previous_end.is_some_and(|end| end > extent.file_offset) {
                return Err(BtrfsError::InvalidFileExtentRange);
            }
            previous_end = Some(extent.file_range_end(sector_size)?);
            self.apply_extent(&extent, &mut output, verify_checksums)?;
        }
        Ok(output)
    }

    fn apply_extent(
        &mut self,
        extent: &FileExtent,
        output: &mut [u8],
        verify_checksums: bool,
    ) -> Result<()> {
        if extent.kind == ExtentKind::Preallocated
            || (extent.kind == ExtentKind::Regular && extent.disk_logical == 0)
        {
            return Ok(());
        }

        let declared_length = if extent.kind == ExtentKind::Inline {
            extent.ram_bytes
        } else {
            extent.logical_bytes
        };
        let copy_length = extent_copy_length(output, extent.file_offset, declared_length)?;
        if copy_length == 0 {
            return Ok(());
        }

        let data = match extent.kind {
            ExtentKind::Inline => decompress(
                &extent.inline_data,
                extent.compression,
                copy_length,
                self.superblock().sector_size(),
            )?,
            ExtentKind::Regular => {
                self.read_regular_extent(extent, copy_length, verify_checksums)?
            }
            ExtentKind::Preallocated => return Ok(()),
        };

        let source_offset =
            if extent.kind == ExtentKind::Regular && extent.compression != Compression::None {
                usize::try_from(extent.extent_offset).map_err(|_| BtrfsError::IntegerOverflow)?
            } else {
                0
            };
        copy_extent(
            output,
            extent.file_offset,
            &data,
            source_offset,
            copy_length,
        )
    }

    fn read_regular_extent(
        &mut self,
        extent: &FileExtent,
        copy_length: u64,
        verify_checksums: bool,
    ) -> Result<Vec<u8>> {
        if extent.compression == Compression::None {
            let (logical, length) =
                uncompressed_read_window(extent, copy_length, self.superblock().sector_size())?;
            return self.read_extent_bytes(logical, length, verify_checksums);
        }

        if extent.disk_bytes > self.superblock().total_bytes() {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        let disk_length =
            usize::try_from(extent.disk_bytes).map_err(|_| BtrfsError::IntegerOverflow)?;
        let encoded = self.read_extent_bytes(extent.disk_logical, disk_length, verify_checksums)?;
        let required_output = extent
            .extent_offset
            .checked_add(copy_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if required_output > extent.ram_bytes {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        decompress(
            &encoded,
            extent.compression,
            required_output,
            self.superblock().sector_size(),
        )
        .map_err(|error| add_extent_context(error, extent))
    }

    fn read_extent_bytes(
        &mut self,
        logical: u64,
        length: usize,
        verify_checksums: bool,
    ) -> Result<Vec<u8>> {
        let replica_count = if verify_checksums {
            self.logical_replica_count(logical)?
        } else {
            1
        };
        let reported_size =
            u64::try_from(length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
        let mut data = zeroed_buffer(length, reported_size)?;
        let mut checksum_error = None;
        for replica in 0..replica_count {
            self.read_logical_exact_from_replica(logical, &mut data, replica)?;
            if !verify_checksums {
                return Ok(data);
            }
            match self.verify_data_checksums(logical, &data) {
                Ok(()) => return Ok(data),
                Err(error @ BtrfsError::InvalidChecksum { .. }) => {
                    checksum_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(checksum_error.unwrap_or(BtrfsError::LogicalAddressUnmapped { logical }))
    }
}

fn uncompressed_read_window(
    extent: &FileExtent,
    copy_length: u64,
    sector_size: u32,
) -> Result<(u64, usize)> {
    if sector_size == 0 {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let sector_size = u64::from(sector_size);
    let read_length = copy_length
        .checked_add(sector_size - 1)
        .ok_or(BtrfsError::IntegerOverflow)?
        / sector_size
        * sector_size;
    let disk_end = extent
        .extent_offset
        .checked_add(read_length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if disk_end > extent.disk_bytes {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let logical = extent
        .disk_logical
        .checked_add(extent.extent_offset)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let length = usize::try_from(read_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    Ok((logical, length))
}

fn extent_copy_length(output: &[u8], file_offset: u64, declared_length: u64) -> Result<u64> {
    let output_length = u64::try_from(output.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
    if file_offset >= output_length {
        return Ok(0);
    }
    Ok(declared_length.min(output_length - file_offset))
}

fn copy_extent(
    output: &mut [u8],
    file_offset: u64,
    source: &[u8],
    source_offset: usize,
    declared_length: u64,
) -> Result<()> {
    let destination_start =
        usize::try_from(file_offset).map_err(|_| BtrfsError::IntegerOverflow)?;
    if destination_start >= output.len() {
        return Ok(());
    }
    let declared = usize::try_from(declared_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    let source_end = source_offset
        .checked_add(declared)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if source_end > source.len() {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let writable = declared.min(output.len() - destination_start);
    output[destination_start..destination_start + writable]
        .copy_from_slice(&source[source_offset..source_offset + writable]);
    Ok(())
}

pub(crate) fn decompress(
    data: &[u8],
    compression: Compression,
    output_length: u64,
    sector_size: u32,
) -> Result<Vec<u8>> {
    if compression == Compression::None {
        return copy_buffer(data);
    }

    #[cfg(feature = "std")]
    {
        decompress_with_std(data, compression, output_length, sector_size)
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = (data, output_length, sector_size);
        Err(BtrfsError::CompressionUnavailable {
            compression: compression.raw(),
        })
    }
}

#[cfg(feature = "std")]
fn decompress_with_std(
    data: &[u8],
    compression: Compression,
    output_length: u64,
    sector_size: u32,
) -> Result<Vec<u8>> {
    let output_length = usize::try_from(output_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    match compression {
        Compression::None => copy_buffer(data),
        Compression::Zlib => {
            let mut decoder = flate2::read::ZlibDecoder::new(data);
            read_decoded_exact(&mut decoder, output_length, compression)
        }
        Compression::Zstd => {
            // The kernel ends decoding at the first frame and ignores the
            // sector padding that fills `disk_num_bytes`. The zstd crate
            // otherwise assumes concatenated frames and treats that padding
            // as another frame header.
            let mut decoder = zstd::stream::read::Decoder::new(data)
                .map_err(|error| {
                    decode_error(
                        compression,
                        alloc::format!(
                            "{error}; encoded length {}, prefix {:02x?}",
                            data.len(),
                            data.get(..8).unwrap_or(data)
                        ),
                    )
                })?
                .single_frame();
            read_decoded_exact(&mut decoder, output_length, compression)
                .map_err(|error| add_zstd_frame_context(error, data))
        }
        Compression::Lzo => decompress_lzo(
            data,
            output_length,
            usize::try_from(sector_size).map_err(|_| BtrfsError::IntegerOverflow)?,
        ),
    }
}

#[cfg(feature = "std")]
fn read_decoded_exact(
    decoder: &mut impl std::io::Read,
    output_length: usize,
    compression: Compression,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let output_size =
        u64::try_from(output_length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| BtrfsError::FileTooLarge { size: output_size })?;
    let limit = u64::try_from(output_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    decoder
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| decode_error(compression, error.to_string()))?;
    if output.len() != output_length {
        return Err(decode_error(
            compression,
            alloc::format!(
                "decoded {} byte(s), but the extent requires {output_length}",
                output.len()
            ),
        ));
    }
    Ok(output)
}

#[cfg(feature = "std")]
fn decompress_lzo(data: &[u8], output_length: usize, sector_size: usize) -> Result<Vec<u8>> {
    if data.len() < 4 || sector_size < 4 {
        return Err(decode_error(Compression::Lzo, "truncated LZO header"));
    }
    let total_length = usize::try_from(u32::from_le_bytes(
        data[..4]
            .try_into()
            .map_err(|_| decode_error(Compression::Lzo, "truncated LZO length"))?,
    ))
    .map_err(|_| BtrfsError::IntegerOverflow)?;
    if total_length > data.len() {
        return Err(decode_error(
            Compression::Lzo,
            "LZO total length exceeds the extent",
        ));
    }

    let output_size =
        u64::try_from(output_length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| BtrfsError::FileTooLarge { size: output_size })?;
    let mut position = 4_usize;
    while position < total_length && output.len() < output_length {
        let sector_remaining = sector_size - (position % sector_size);
        if sector_remaining < 4 {
            if total_length - position <= sector_remaining {
                break;
            }
            position = position
                .checked_add(sector_remaining)
                .ok_or(BtrfsError::IntegerOverflow)?;
        }
        let header_end = position.checked_add(4).ok_or(BtrfsError::IntegerOverflow)?;
        if header_end > total_length {
            return Err(decode_error(
                Compression::Lzo,
                "truncated LZO segment header",
            ));
        }
        let segment_length = usize::try_from(u32::from_le_bytes(
            data[position..header_end]
                .try_into()
                .map_err(|_| decode_error(Compression::Lzo, "truncated LZO segment length"))?,
        ))
        .map_err(|_| BtrfsError::IntegerOverflow)?;
        position = header_end;
        let segment_end = position
            .checked_add(segment_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if segment_end > total_length {
            return Err(decode_error(Compression::Lzo, "truncated LZO segment"));
        }
        let decoded_size =
            u64::try_from(sector_size).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
        let mut decoded = zeroed_buffer(sector_size, decoded_size)?;
        let decoded_length =
            lzokay::decompress::decompress(&data[position..segment_end], &mut decoded)
                .map_err(|error| decode_error(Compression::Lzo, alloc::format!("{error:?}")))?;
        let required = output_length - output.len();
        output.extend_from_slice(&decoded[..decoded_length.min(required)]);
        position = segment_end;
    }
    if output.len() != output_length {
        return Err(decode_error(
            Compression::Lzo,
            "decoded LZO length differs from ram_bytes",
        ));
    }
    Ok(output)
}

fn zeroed_buffer(length: usize, reported_size: u64) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| BtrfsError::FileTooLarge {
            size: reported_size,
        })?;
    output.resize(length, 0);
    Ok(output)
}

fn copy_buffer(data: &[u8]) -> Result<Vec<u8>> {
    let reported_size =
        u64::try_from(data.len()).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(data.len())
        .map_err(|_| BtrfsError::FileTooLarge {
            size: reported_size,
        })?;
    output.extend_from_slice(data);
    Ok(output)
}

#[cfg(feature = "std")]
fn decode_error(compression: Compression, reason: impl Into<alloc::string::String>) -> BtrfsError {
    BtrfsError::DecompressionFailed {
        compression: compression.raw(),
        reason: reason.into(),
    }
}

fn add_extent_context(error: BtrfsError, extent: &FileExtent) -> BtrfsError {
    match error {
        BtrfsError::DecompressionFailed {
            compression,
            reason,
        } => BtrfsError::DecompressionFailed {
            compression,
            reason: alloc::format!(
                "{reason}; disk logical {:#x}, disk bytes {}, ram bytes {}, \
                 extent offset {}, logical bytes {}",
                extent.disk_logical,
                extent.disk_bytes,
                extent.ram_bytes,
                extent.extent_offset,
                extent.logical_bytes
            ),
        },
        other => other,
    }
}

#[cfg(feature = "std")]
fn add_zstd_frame_context(error: BtrfsError, data: &[u8]) -> BtrfsError {
    let frame_offsets: Vec<usize> = data
        .windows(4)
        .enumerate()
        .filter_map(|(offset, window)| (window == [0x28, 0xb5, 0x2f, 0xfd]).then_some(offset))
        .collect();
    match error {
        BtrfsError::DecompressionFailed {
            compression,
            reason,
        } => BtrfsError::DecompressionFailed {
            compression,
            reason: alloc::format!("{reason}; zstd frame offsets {frame_offsets:?}"),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_extent_clamps_tail_to_file_size() {
        let mut output = [0_u8; 5];
        copy_extent(&mut output, 3, b"abcd", 0, 4).expect("copy");
        assert_eq!(&output, b"\0\0\0ab");
    }

    #[test]
    fn copy_extent_selects_shared_extent_window() {
        let mut output = [0_u8; 4];
        copy_extent(&mut output, 0, b"prefixDATA", 6, 4).expect("copy");
        assert_eq!(&output, b"DATA");
    }

    #[test]
    fn sector_rounded_tail_is_clamped_to_inode_size() {
        let output = alloc::vec![0_u8; 1_551_104];
        assert_eq!(
            extent_copy_length(&output, 1_441_792, 110_592).expect("tail length"),
            109_312
        );
    }

    #[test]
    fn impossible_buffer_capacity_is_reported_without_allocating() {
        assert!(matches!(
            zeroed_buffer(usize::MAX, u64::MAX),
            Err(BtrfsError::FileTooLarge { size: u64::MAX })
        ));
    }

    #[test]
    fn uncompressed_extent_reads_only_the_selected_sector_window() {
        let extent = FileExtent {
            file_offset: 0,
            ram_bytes: 16_384,
            compression: Compression::None,
            kind: ExtentKind::Regular,
            inline_data: Vec::new(),
            disk_logical: 0x10_0000,
            disk_bytes: 16_384,
            extent_offset: 4096,
            logical_bytes: 4096,
        };

        assert_eq!(
            uncompressed_read_window(&extent, 1, 4096).expect("one sector"),
            (0x10_1000, 4096)
        );
    }

    #[test]
    fn uncompressed_extent_rejects_a_window_beyond_disk_bytes() {
        let extent = FileExtent {
            file_offset: 0,
            ram_bytes: 8192,
            compression: Compression::None,
            kind: ExtentKind::Regular,
            inline_data: Vec::new(),
            disk_logical: 0x10_0000,
            disk_bytes: 4096,
            extent_offset: 4096,
            logical_bytes: 4096,
        };

        assert!(matches!(
            uncompressed_read_window(&extent, 1, 4096),
            Err(BtrfsError::InvalidFileExtentRange)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn zstd_decoder_stops_before_sector_padding() {
        let source = alloc::vec![0x5a_u8; 128 * 1024];
        let mut encoded = zstd::stream::encode_all(source.as_slice(), 3).expect("compress");
        encoded.resize(encoded.len().next_multiple_of(4096), 0);

        let decoded = decompress(
            &encoded,
            Compression::Zstd,
            u64::try_from(source.len()).expect("source length"),
            4096,
        )
        .expect("decode padded extent");
        assert_eq!(decoded, source);
    }
}
