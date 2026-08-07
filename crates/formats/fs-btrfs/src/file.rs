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
        self.read_file_range_known_size(
            entry,
            inode.size(),
            inode.has_data_checksums(),
            0,
            &mut output,
        )?;
        Ok(output)
    }

    /// Read a bounded range of a regular file or symbolic-link target.
    ///
    /// At most `buffer.len()` bytes are written. Sparse and preallocated
    /// ranges produce zeroes, and reads at or beyond the inode size return
    /// zero. Compressed extents require the `std` feature and use at most
    /// Btrfs's 128 KiB compressed-extent limit as temporary storage.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotAFile`] for other inode kinds, or a tree,
    /// mapping, encoding, decompression, checksum, range, or I/O error.
    pub fn read_file_range(
        &mut self,
        entry: BtrfsEntry,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let inode = self.inode(entry)?;
        if !inode.file_type().has_file_data() {
            return Err(BtrfsError::NotAFile);
        }
        self.read_file_range_known_size(
            entry,
            inode.size(),
            inode.has_data_checksums(),
            offset,
            buffer,
        )
    }

    fn read_file_range_known_size(
        &mut self,
        entry: BtrfsEntry,
        file_size: u64,
        verify_checksums: bool,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let buffer_length = u64::try_from(buffer.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
        let read_length = file_size.saturating_sub(offset).min(buffer_length);
        let read_length = usize::try_from(read_length).map_err(|_| BtrfsError::IntegerOverflow)?;
        if read_length == 0 {
            return Ok(0);
        }
        let output = &mut buffer[..read_length];
        output.fill(0);
        let range_end = offset
            .checked_add(u64::try_from(read_length).map_err(|_| BtrfsError::IntegerOverflow)?)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let root = self.lookup_tree_root(entry.tree_id())?;
        let start_key = DiskKey {
            object_id: entry.object_id(),
            item_type: EXTENT_DATA_KEY,
            offset,
        };
        let end_key = DiskKey {
            object_id: entry.object_id(),
            item_type: EXTENT_DATA_KEY,
            offset: range_end
                .checked_sub(1)
                .ok_or(BtrfsError::IntegerOverflow)?,
        };
        let predecessor = self.find_predecessor(root, start_key)?.filter(|item| {
            item.key.object_id == entry.object_id() && item.key.item_type == EXTENT_DATA_KEY
        });
        let collection_start = predecessor.as_ref().map_or(start_key, |item| item.key);
        let mut items = self.collect_items_raw(root, collection_start, end_key)?;
        if let Some(predecessor) = predecessor
            && items.first().is_none_or(|item| item.key != predecessor.key)
        {
            items.insert(0, predecessor);
        }

        let sector_size = self.superblock().sector_size();
        let committed = parse_extent_layer(items, sector_size)?;
        for extent in &committed {
            self.apply_extent_range(extent, offset, output, verify_checksums)?;
        }
        let logged =
            self.logged_file_extents(entry.tree_id(), entry.object_id(), offset, end_key.offset);
        let logged = parse_extent_layer(logged, sector_size)?;
        for extent in &logged {
            clear_extent_range(extent, offset, output)?;
            self.apply_extent_range(extent, offset, output, verify_checksums)?;
        }
        Ok(read_length)
    }

    fn apply_extent_range(
        &mut self,
        extent: &FileExtent,
        request_offset: u64,
        output: &mut [u8],
        verify_checksums: bool,
    ) -> Result<()> {
        let Some(window) = extent_window(extent, request_offset, output.len())? else {
            return Ok(());
        };
        if extent.kind == ExtentKind::Preallocated
            || (extent.kind == ExtentKind::Regular && extent.disk_logical == 0)
        {
            return Ok(());
        }

        match extent.kind {
            ExtentKind::Inline if extent.compression == Compression::None => copy_window(
                output,
                window.destination_start,
                &extent.inline_data,
                usize::try_from(window.extent_offset).map_err(|_| BtrfsError::IntegerOverflow)?,
                window.length,
            ),
            ExtentKind::Inline => {
                let required_output = window
                    .extent_offset
                    .checked_add(
                        u64::try_from(window.length).map_err(|_| BtrfsError::IntegerOverflow)?,
                    )
                    .ok_or(BtrfsError::IntegerOverflow)?;
                if required_output > extent.ram_bytes {
                    return Err(BtrfsError::InvalidFileExtentRange);
                }
                let decoded = decompress(
                    &extent.inline_data,
                    extent.compression,
                    required_output,
                    self.superblock().sector_size(),
                )?;
                copy_window(
                    output,
                    window.destination_start,
                    &decoded,
                    usize::try_from(window.extent_offset)
                        .map_err(|_| BtrfsError::IntegerOverflow)?,
                    window.length,
                )
            }
            ExtentKind::Regular => {
                let (data, source_offset) =
                    self.read_regular_extent_range(extent, window, verify_checksums)?;
                copy_window(
                    output,
                    window.destination_start,
                    &data,
                    source_offset,
                    window.length,
                )
            }
            ExtentKind::Preallocated => Ok(()),
        }
    }

    fn read_regular_extent_range(
        &mut self,
        extent: &FileExtent,
        window: ExtentWindow,
        verify_checksums: bool,
    ) -> Result<(Vec<u8>, usize)> {
        if extent.compression == Compression::None {
            let (logical, length, source_offset) = uncompressed_read_window(
                extent,
                window.extent_offset,
                window.length,
                self.superblock().sector_size(),
            )?;
            return self
                .read_extent_bytes(logical, length, verify_checksums)
                .map(|data| (data, source_offset));
        }

        if extent.disk_bytes > self.active_total_bytes() {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        let disk_length =
            usize::try_from(extent.disk_bytes).map_err(|_| BtrfsError::IntegerOverflow)?;
        let encoded = self.read_extent_bytes(extent.disk_logical, disk_length, verify_checksums)?;
        let window_length =
            u64::try_from(window.length).map_err(|_| BtrfsError::IntegerOverflow)?;
        let required_output = extent
            .extent_offset
            .checked_add(window.extent_offset)
            .and_then(|offset| offset.checked_add(window_length))
            .ok_or(BtrfsError::IntegerOverflow)?;
        if required_output > extent.ram_bytes {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        let decoded = decompress(
            &encoded,
            extent.compression,
            required_output,
            self.superblock().sector_size(),
        )
        .map_err(|error| add_extent_context(error, extent))?;
        let source_offset = extent
            .extent_offset
            .checked_add(window.extent_offset)
            .ok_or(BtrfsError::IntegerOverflow)?;
        Ok((
            decoded,
            usize::try_from(source_offset).map_err(|_| BtrfsError::IntegerOverflow)?,
        ))
    }

    fn read_extent_bytes(
        &mut self,
        logical: u64,
        length: usize,
        verify_checksums: bool,
    ) -> Result<Vec<u8>> {
        let replica_count = if verify_checksums {
            self.data_replica_count(logical)?
        } else {
            1
        };
        let reported_size =
            u64::try_from(length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
        let mut data = zeroed_buffer(length, reported_size)?;
        let mut last_error = None;
        for replica in 0..replica_count {
            if let Err(error) =
                self.read_data_logical_exact_from_replica(logical, &mut data, replica)
            {
                last_error = Some(error);
                continue;
            }
            if !verify_checksums {
                return Ok(data);
            }
            match self.verify_data_checksums(logical, &data) {
                Ok(()) => return Ok(data),
                Err(error @ BtrfsError::InvalidChecksum { .. }) => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or(BtrfsError::LogicalAddressUnmapped { logical }))
    }
}

fn parse_extent_layer(
    items: Vec<crate::tree::TreeItem>,
    sector_size: u32,
) -> Result<Vec<FileExtent>> {
    let mut extents = Vec::with_capacity(items.len());
    let mut previous_end = None;
    for item in items {
        let extent = FileExtent::parse(item.key, &item.data, sector_size)?;
        if previous_end.is_some_and(|end| end > extent.file_offset) {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        previous_end = Some(extent.file_range_end(sector_size)?);
        extents.push(extent);
    }
    Ok(extents)
}

fn clear_extent_range(extent: &FileExtent, request_offset: u64, output: &mut [u8]) -> Result<()> {
    let Some(window) = extent_window(extent, request_offset, output.len())? else {
        return Ok(());
    };
    let end = window
        .destination_start
        .checked_add(window.length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    output
        .get_mut(window.destination_start..end)
        .ok_or(BtrfsError::InvalidFileExtentRange)?
        .fill(0);
    Ok(())
}

#[derive(Clone, Copy)]
struct ExtentWindow {
    destination_start: usize,
    extent_offset: u64,
    length: usize,
}

fn extent_window(
    extent: &FileExtent,
    request_offset: u64,
    output_length: usize,
) -> Result<Option<ExtentWindow>> {
    let extent_length = if extent.kind == ExtentKind::Inline {
        extent.ram_bytes
    } else {
        extent.logical_bytes
    };
    let extent_end = extent
        .file_offset
        .checked_add(extent_length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let request_end = request_offset
        .checked_add(u64::try_from(output_length).map_err(|_| BtrfsError::IntegerOverflow)?)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let overlap_start = extent.file_offset.max(request_offset);
    let overlap_end = extent_end.min(request_end);
    if overlap_start >= overlap_end {
        return Ok(None);
    }
    Ok(Some(ExtentWindow {
        destination_start: usize::try_from(overlap_start - request_offset)
            .map_err(|_| BtrfsError::IntegerOverflow)?,
        extent_offset: overlap_start - extent.file_offset,
        length: usize::try_from(overlap_end - overlap_start)
            .map_err(|_| BtrfsError::IntegerOverflow)?,
    }))
}

fn uncompressed_read_window(
    extent: &FileExtent,
    range_offset: u64,
    copy_length: usize,
    sector_size: u32,
) -> Result<(u64, usize, usize)> {
    if sector_size == 0 {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let sector_size = u64::from(sector_size);
    let extent_offset = extent
        .extent_offset
        .checked_add(range_offset)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let requested_logical = extent
        .disk_logical
        .checked_add(extent_offset)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let logical = requested_logical - (requested_logical % sector_size);
    let source_offset = requested_logical - logical;
    let required_length = source_offset
        .checked_add(u64::try_from(copy_length).map_err(|_| BtrfsError::IntegerOverflow)?)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let read_length = required_length
        .checked_add(sector_size - 1)
        .ok_or(BtrfsError::IntegerOverflow)?
        / sector_size
        * sector_size;
    let disk_start = logical
        .checked_sub(extent.disk_logical)
        .ok_or(BtrfsError::InvalidFileExtentRange)?;
    let disk_end = disk_start
        .checked_add(read_length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if disk_end > extent.disk_bytes {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let length = usize::try_from(read_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    let source_offset = usize::try_from(source_offset).map_err(|_| BtrfsError::IntegerOverflow)?;
    Ok((logical, length, source_offset))
}

fn copy_window(
    output: &mut [u8],
    destination_start: usize,
    source: &[u8],
    source_offset: usize,
    length: usize,
) -> Result<()> {
    let source_end = source_offset
        .checked_add(length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let destination_end = destination_start
        .checked_add(length)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if source_end > source.len() || destination_end > output.len() {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    output[destination_start..destination_end].copy_from_slice(&source[source_offset..source_end]);
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
    fn extent_window_clamps_tail_to_requested_range() {
        let extent = FileExtent {
            file_offset: 3,
            ram_bytes: 4,
            compression: Compression::None,
            kind: ExtentKind::Regular,
            inline_data: Vec::new(),
            disk_logical: 4096,
            disk_bytes: 4096,
            extent_offset: 0,
            logical_bytes: 4,
        };
        let window = extent_window(&extent, 0, 5)
            .expect("window")
            .expect("overlap");
        assert_eq!(window.destination_start, 3);
        assert_eq!(window.extent_offset, 0);
        assert_eq!(window.length, 2);
    }

    #[test]
    fn copy_window_selects_shared_extent_bytes() {
        let mut output = [0_u8; 4];
        copy_window(&mut output, 0, b"prefixDATA", 6, 4).expect("copy");
        assert_eq!(&output, b"DATA");
    }

    #[test]
    fn sector_rounded_tail_is_clamped_to_inode_size() {
        let extent = FileExtent {
            file_offset: 1_441_792,
            ram_bytes: 110_592,
            compression: Compression::None,
            kind: ExtentKind::Regular,
            inline_data: Vec::new(),
            disk_logical: 4096,
            disk_bytes: 110_592,
            extent_offset: 0,
            logical_bytes: 110_592,
        };
        let window = extent_window(&extent, 0, 1_551_104)
            .expect("window")
            .expect("overlap");
        assert_eq!(window.length, 109_312);
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
            uncompressed_read_window(&extent, 1, 1, 4096).expect("one byte"),
            (0x10_1000, 4096, 1)
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
            uncompressed_read_window(&extent, 0, 1, 4096),
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
