//! Mechanics shared by the format-specific adapters.

use fsmnt_core::{FsError, FsResult};

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

/// Read at most `length` bytes through a parser-specific read operation.
///
/// Parser file handles all expose the same incremental-read shape but use
/// different error types and require different volume-reader arguments. The
/// adapter supplies those details in `read`; this helper owns the common
/// allocation, EOF handling, and truncation.
pub(crate) fn read_up_to(
    length: u64,
    mut read: impl FnMut(&mut [u8]) -> FsResult<usize>,
) -> FsResult<Vec<u8>> {
    let size = usize::try_from(length)
        .map_err(|_| FsError::Filesystem("file too large to read in one call".to_string()))?;
    let mut buffer = vec![0_u8; size];
    let mut total = 0;

    while total < size {
        let bytes_read = read(&mut buffer[total..])?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read > size - total {
            return Err(FsError::Filesystem(
                "filesystem parser returned an invalid read length".to_string(),
            ));
        }
        total += bytes_read;
    }

    buffer.truncate(total);
    Ok(buffer)
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
}
