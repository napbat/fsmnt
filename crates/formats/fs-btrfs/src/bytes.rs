//! Checked subslices for variable-length Btrfs structures.

use crate::{BtrfsError, Result};

pub(crate) fn slice(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or(BtrfsError::IntegerOverflow)?;
    data.get(offset..end).ok_or(BtrfsError::BufferTooSmall {
        expected: end,
        actual: data.len(),
    })
}
