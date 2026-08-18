//! Mechanics shared by the format-specific adapters.

use fsmnt_core::{FsError, FsResult};
use fsmnt_parser_core::io::FsReadSeek;

/// Convert a lookup result into the `TargetFilesystem::try_exists` contract.
pub(crate) fn found<T>(result: FsResult<T>) -> FsResult<bool> {
    match result {
        Ok(_) => Ok(true),
        Err(FsError::NotFound(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Convert a successful lookup with a predicate into a `try_is_*` result.
pub(crate) fn found_and<T>(
    result: FsResult<T>,
    predicate: impl FnOnce(T) -> bool,
) -> FsResult<bool> {
    match result {
        Ok(value) => Ok(predicate(value)),
        Err(FsError::NotFound(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Largest single allocation `read_up_to` makes before it has seen data:
/// files past this size are read in growing steps instead of one buffer.
///
/// The declared length comes from on-disk metadata, and on damaged media a
/// corrupt inode can claim petabytes; allocating that up front aborts the
/// whole process (an allocation failure is not a catchable panic), taking
/// the mounted volume with it. Growing the buffer as bytes actually arrive
/// bounds the damage to "this read fails".
const READ_CHUNK_LIMIT: usize = 64 * 1024 * 1024;

/// Read at most `length` bytes through a parser-specific read operation.
///
/// Parser file handles all expose the same incremental-read shape but use
/// different error types and require different volume-reader arguments. The
/// adapter supplies those details in `read`; this helper owns the common
/// allocation, EOF handling, and truncation.
///
/// The buffer is sized to `length` for ordinary files and grown in
/// [`READ_CHUNK_LIMIT`] steps for anything larger, so a metadata field that
/// lies about a file's size cannot exhaust memory before a single byte has
/// been read; a read that ends early simply yields the bytes that were
/// there.
pub(crate) fn read_up_to(
    length: u64,
    mut read: impl FnMut(&mut [u8]) -> FsResult<usize>,
) -> FsResult<Vec<u8>> {
    let size = usize::try_from(length)
        .map_err(|_| FsError::Filesystem("file too large to read in one call".to_string()))?;
    let mut buffer = vec![0_u8; size.min(READ_CHUNK_LIMIT)];
    let mut total = 0;

    while total < size {
        if total == buffer.len() {
            // Grow only once the bytes read so far have filled what we have.
            let grown = buffer.len().saturating_add(READ_CHUNK_LIMIT).min(size);
            buffer
                .try_reserve_exact(grown - buffer.len())
                .map_err(|_| {
                    FsError::Filesystem(format!(
                        "cannot allocate {grown} bytes to read a file that claims {length} bytes"
                    ))
                })?;
            buffer.resize(grown, 0);
        }
        let bytes_read = read(&mut buffer[total..])?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read > buffer.len() - total {
            return Err(FsError::Filesystem(
                "filesystem parser returned an invalid read length".to_string(),
            ));
        }
        total += bytes_read;
    }

    buffer.truncate(total);
    Ok(buffer)
}

/// Read `buffer.len()` bytes at `offset` from a positioned parser stream:
/// seek, then read until the buffer is full or the stream ends.
///
/// This is what every adapter's `TargetFilesystem::read_at` should be built
/// on. The trait's default `read_at` calls `read` — the *whole file* — for
/// every chunk the mount backend asks for, which makes copying a large file
/// quadratic in I/O and allocates the entire file per chunk; the parsers
/// all offer a seekable stream, so a positioned read is the honest
/// primitive. Returns 0 at or past the end of the stream, like the trait
/// requires.
pub(crate) fn read_at_through<R, S: FsReadSeek<R>>(
    stream: &mut S,
    reader: &mut R,
    offset: u64,
    buffer: &mut [u8],
    map_error: impl Fn(S::Error) -> FsError,
) -> FsResult<usize>
where
    R: std::io::Read + std::io::Seek,
{
    if buffer.is_empty() || offset >= stream.len() {
        return Ok(0);
    }
    stream
        .seek(reader, std::io::SeekFrom::Start(offset))
        .map_err(&map_error)?;
    let mut total = 0;
    while total < buffer.len() {
        let read = stream
            .read(reader, &mut buffer[total..])
            .map_err(&map_error)?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_distinguishes_absence_from_other_errors() {
        assert!(found(Ok(())).expect("successful lookup"));
        assert!(!found::<()>(Err(FsError::NotFound("/missing".to_string()))).expect("not found"));
        assert!(matches!(
            found::<()>(Err(FsError::NotAFile("/directory".to_string()))),
            Err(FsError::NotAFile(_))
        ));
    }

    #[test]
    fn found_and_applies_the_predicate_only_to_present_values() {
        assert!(found_and(Ok(2_u8), |value| value.is_multiple_of(2)).expect("present value"));
        assert!(
            !found_and::<u8>(
                Err(FsError::NotFound("/missing".to_string())),
                |_| unreachable!("missing values do not reach the predicate"),
            )
            .expect("not found")
        );
    }

    #[test]
    fn read_up_to_combines_short_parser_reads() {
        let source = b"abcdef";
        let mut offset = 0;
        let data = read_up_to(6, |buffer| {
            let count = buffer.len().min(2);
            buffer[..count].copy_from_slice(&source[offset..offset + count]);
            offset += count;
            Ok(count)
        })
        .expect("read succeeds");

        assert_eq!(data, source);
    }

    #[test]
    fn read_up_to_truncates_at_early_eof() {
        let mut first = true;
        let data = read_up_to(8, |buffer| {
            if !first {
                return Ok(0);
            }
            first = false;
            buffer[..3].copy_from_slice(b"abc");
            Ok(3)
        })
        .expect("short file remains readable");

        assert_eq!(data, b"abc");
    }

    #[test]
    fn read_up_to_does_not_preallocate_an_absurd_declared_length() {
        // A corrupt inode claiming petabytes used to abort the process on
        // allocation. The buffer must grow with the data instead, so a
        // parser that stops early leaves a small, correct result.
        let mut calls = 0;
        let data = read_up_to(u64::MAX / 4, |buffer| {
            calls += 1;
            if calls > 1 {
                return Ok(0);
            }
            let count = buffer.len().min(5);
            buffer[..count].copy_from_slice(b"hello");
            Ok(count)
        })
        .expect("a lying length must not be fatal");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn read_up_to_grows_past_the_first_chunk_when_data_keeps_coming() {
        // Total > READ_CHUNK_LIMIT, delivered in pieces: every byte arrives.
        let total = READ_CHUNK_LIMIT + 3;
        let mut sent = 0;
        let data = read_up_to(total as u64, |buffer| {
            let remaining = total - sent;
            let count = buffer.len().min(remaining).min(1 << 20);
            buffer[..count].fill(0xAB);
            sent += count;
            Ok(count)
        })
        .expect("large read");
        assert_eq!(data.len(), total);
        assert!(data.iter().all(|&b| b == 0xAB));
    }
}
