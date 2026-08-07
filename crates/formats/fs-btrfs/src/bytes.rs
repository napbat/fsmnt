//! Checked little-endian field readers for packed Btrfs structures.

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

pub(crate) fn array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    let bytes = slice(data, offset, N)?;
    let mut result = [0_u8; N];
    result.copy_from_slice(bytes);
    Ok(result)
}

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, offset)?))
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, offset)?))
}

pub(crate) fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, offset)?))
}

pub(crate) fn i64_at(data: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_le_bytes(array(data, offset)?))
}
