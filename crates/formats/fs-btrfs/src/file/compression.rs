//! Btrfs extent decompression with reusable output storage.

use alloc::vec::Vec;

use crate::item::Compression;
use crate::{BtrfsError, Result};

/// Decompress one extent into a newly allocated buffer.
#[cfg(feature = "fuzzing")]
pub(crate) fn decompress(
    data: &[u8],
    compression: Compression,
    output_length: u64,
    sector_size: u32,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    decompress_into(data, compression, output_length, sector_size, &mut output)?;
    Ok(output)
}

/// Decompress one extent while retaining `output`'s allocation.
pub(super) fn decompress_into(
    data: &[u8],
    compression: Compression,
    output_length: u64,
    sector_size: u32,
    output: &mut Vec<u8>,
) -> Result<()> {
    if compression == Compression::None {
        replace_from_slice(output, data)?;
        return Ok(());
    }

    #[cfg(feature = "std")]
    {
        decompress_with_std(data, compression, output_length, sector_size, output)
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = (data, output_length, sector_size, output);
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
    output: &mut Vec<u8>,
) -> Result<()> {
    let output_length = usize::try_from(output_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    match compression {
        Compression::None => replace_from_slice(output, data),
        Compression::Zlib => {
            let mut decoder = flate2::read::ZlibDecoder::new(data);
            read_decoded_exact(&mut decoder, output_length, compression, output)
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
            read_decoded_exact(&mut decoder, output_length, compression, output)
                .map_err(|error| add_zstd_frame_context(error, data))
        }
        Compression::Lzo => decompress_lzo(
            data,
            output_length,
            usize::try_from(sector_size).map_err(|_| BtrfsError::IntegerOverflow)?,
            output,
        ),
    }
}

#[cfg(feature = "std")]
fn read_decoded_exact(
    decoder: &mut impl std::io::Read,
    output_length: usize,
    compression: Compression,
    output: &mut Vec<u8>,
) -> Result<()> {
    use std::io::Read as _;

    clear_and_reserve(output, output_length)?;
    let limit = u64::try_from(output_length).map_err(|_| BtrfsError::IntegerOverflow)?;
    decoder
        .take(limit)
        .read_to_end(output)
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
    Ok(())
}

#[cfg(feature = "std")]
fn decompress_lzo(
    data: &[u8],
    output_length: usize,
    sector_size: usize,
    output: &mut Vec<u8>,
) -> Result<()> {
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

    clear_and_reserve(output, output_length)?;
    let decoded_size =
        u64::try_from(sector_size).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    let mut decoded = super::zeroed_buffer(sector_size, decoded_size)?;
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
    Ok(())
}

fn clear_and_reserve(output: &mut Vec<u8>, length: usize) -> Result<()> {
    let reported_size =
        u64::try_from(length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    output.clear();
    output
        .try_reserve_exact(length)
        .map_err(|_| BtrfsError::FileTooLarge {
            size: reported_size,
        })
}

fn replace_from_slice(output: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    clear_and_reserve(output, data.len())?;
    output.extend_from_slice(data);
    Ok(())
}

#[cfg(feature = "std")]
fn decode_error(compression: Compression, reason: impl Into<alloc::string::String>) -> BtrfsError {
    BtrfsError::DecompressionFailed {
        compression: compression.raw(),
        reason: reason.into(),
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

    #[cfg(feature = "std")]
    #[test]
    fn zstd_decoder_stops_before_sector_padding_and_reuses_output() {
        let source = alloc::vec![0x5a_u8; 128 * 1024];
        let mut encoded = zstd::stream::encode_all(source.as_slice(), 3).expect("compress");
        encoded.resize(encoded.len().next_multiple_of(4096), 0);
        let mut decoded = Vec::with_capacity(source.len());
        let allocation = decoded.as_ptr();

        decompress_into(
            &encoded,
            Compression::Zstd,
            u64::try_from(source.len()).expect("source length"),
            4096,
            &mut decoded,
        )
        .expect("decode padded extent");

        assert_eq!(decoded, source);
        assert_eq!(decoded.as_ptr(), allocation);
    }
}
