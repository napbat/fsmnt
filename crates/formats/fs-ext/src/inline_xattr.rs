use crate::error::{ExtError, Result};
use crate::inode::{read_u16_le, read_u32_le};

/// Ibody xattr magic: `0xEA020000` stored as little-endian bytes.
const XATTR_MAGIC: u32 = 0xEA02_0000;

/// Name index for `system.*` namespace.
const SYSTEM_NAME_INDEX: u8 = 7;

/// Xattr entry header size: `e_name_len(1)` + `e_name_index(1)` +
/// `e_value_offs(2)` + `e_value_inum(4)` + `e_value_size(4)` + `e_hash(4)`
/// = 16 bytes.
const ENTRY_HEADER_SIZE: usize = 16;

/// Round `n` up to the next 4-byte boundary.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Search the in-inode xattr region for `system.data`.
///
/// Returns the raw value bytes when found, `None` when the region is
/// valid but `system.data` is absent, or `Err(InvalidInlineData)` for
/// malformed inline-relevant state.
///
/// `inode_buf` is the full raw inode bytes.
/// `inode` is used only for error context.
#[cfg(test)]
pub(crate) fn find_system_data(
    inode_buf: &[u8],
    extra_isize: u16,
    inode: u32,
) -> Result<Option<&[u8]>> {
    let xattr_start = 128 + extra_isize as usize;
    if xattr_start + 4 > inode_buf.len() {
        return Ok(None);
    }
    let ibody = &inode_buf[xattr_start..];
    match find_system_data_range(ibody, inode)? {
        Some((offset, len)) => Ok(Some(&ibody[offset..offset + len])),
        None => Ok(None),
    }
}

/// Search an ibody xattr region for `system.data` and return its
/// byte range within `ibody`.
///
/// `ibody` starts at the xattr magic header (offset `128 + extra_isize`
/// in the on-disk inode). Returns `Ok(Some((offset, len)))` where
/// `offset` is relative to the start of `ibody`. Returns `Ok(None)`
/// when the region is valid but `system.data` is absent.
pub(crate) fn find_system_data_range(ibody: &[u8], inode: u32) -> Result<Option<(usize, usize)>> {
    let ibody_len = ibody.len();
    if ibody_len < 8 {
        return Ok(None);
    }

    let magic = read_u32_le(ibody, 0);
    if magic != XATTR_MAGIC {
        return Ok(None);
    }

    let first_entry = 4usize;
    let mut pos = first_entry;

    loop {
        if pos + 2 > ibody_len {
            break;
        }
        if ibody[pos] == 0 && ibody[pos + 1] == 0 {
            break;
        }
        if pos + ENTRY_HEADER_SIZE > ibody_len {
            return Err(ExtError::InvalidInlineData { inode });
        }

        let e_name_len = ibody[pos] as usize;
        let e_name_index = ibody[pos + 1];
        let e_value_offs = read_u16_le(ibody, pos + 2) as usize;
        let e_value_inum = read_u32_le(ibody, pos + 4);
        let e_value_size = read_u32_le(ibody, pos + 8) as usize;

        let name_start = pos + ENTRY_HEADER_SIZE;
        if name_start + e_name_len > ibody_len {
            return Err(ExtError::InvalidInlineData { inode });
        }

        if e_name_index == SYSTEM_NAME_INDEX
            && &ibody[name_start..name_start + e_name_len] == b"data"
        {
            if e_value_inum != 0 {
                return Err(ExtError::InvalidInlineData { inode });
            }
            let value_start = first_entry + e_value_offs;
            if value_start + e_value_size > ibody_len {
                return Err(ExtError::InvalidInlineData { inode });
            }
            return Ok(Some((value_start, e_value_size)));
        }

        pos = align4(name_start + e_name_len);
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INODE_SIZE: u16 = 256;
    const EXTRA_ISIZE: u16 = 32;
    const TEST_INODE: u32 = 42;

    /// Offset where the xattr region starts in the inode buffer.
    const XATTR_START: usize = 128 + EXTRA_ISIZE as usize;
    /// Offset of the first xattr entry (after the 4-byte magic).
    const FIRST_ENTRY: usize = XATTR_START + 4;

    /// Build a minimal 256-byte inode buffer with xattr magic planted.
    fn base_buf() -> Vec<u8> {
        let mut buf = vec![0u8; INODE_SIZE as usize];
        // Plant ibody xattr magic
        buf[XATTR_START..XATTR_START + 4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        buf
    }

    /// Write an xattr entry at `pos` in `buf` and return the aligned
    /// offset of the next entry.
    fn write_entry(
        buf: &mut [u8],
        pos: usize,
        name_index: u8,
        name: &[u8],
        value_offs: u16,
        value_inum: u32,
        value_size: u32,
    ) -> usize {
        buf[pos] = (name.len()).to_le_bytes()[0];
        buf[pos + 1] = name_index;
        buf[pos + 2..pos + 4].copy_from_slice(&value_offs.to_le_bytes());
        buf[pos + 4..pos + 8].copy_from_slice(&value_inum.to_le_bytes());
        buf[pos + 8..pos + 12].copy_from_slice(&value_size.to_le_bytes());
        // e_hash at [12..16] stays zero (already zeroed in base_buf)
        buf[pos + 16..pos + 16 + name.len()].copy_from_slice(name);
        align4(pos + 16 + name.len())
    }

    /// Place a value at the end of the inode buffer (values grow down).
    /// Returns the `e_value_offs` relative to `FIRST_ENTRY`.
    fn place_value(buf: &mut [u8], data: &[u8]) -> u16 {
        let value_start = INODE_SIZE as usize - data.len();
        buf[value_start..value_start + data.len()].copy_from_slice(data);
        u16::try_from(value_start - FIRST_ENTRY).expect("the test fixture value fits in u16")
    }

    // --- system.data present ---

    #[test]
    fn system_data_found() {
        let mut buf = base_buf();
        let data = b"hello inline";
        let offs = place_value(&mut buf, data);
        write_entry(
            &mut buf,
            FIRST_ENTRY,
            SYSTEM_NAME_INDEX,
            b"data",
            offs,
            0,
            u32::try_from(data.len()).expect("the test fixture value fits in u32"),
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert_eq!(result.unwrap().unwrap(), data);
    }

    // --- missing magic -> Ok(None) ---

    #[test]
    fn missing_magic_returns_none() {
        let mut buf = vec![0u8; INODE_SIZE as usize];
        // No magic planted -- all zeros
        buf[XATTR_START..XATTR_START + 4].copy_from_slice(&0u32.to_le_bytes());

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert!(result.unwrap().is_none());
    }

    // --- absent system.data -> Ok(None) ---

    #[test]
    fn no_system_data_entry_returns_none() {
        let mut buf = base_buf();
        // Write a non-matching entry (user namespace, index=1)
        let data = b"something";
        let offs = place_value(&mut buf, data);
        let next = write_entry(
            &mut buf,
            FIRST_ENTRY,
            1,
            b"other",
            offs,
            0,
            u32::try_from(data.len()).expect("the test fixture value fits in u32"),
        );
        // Terminate with zero entry
        buf[next] = 0;
        buf[next + 1] = 0;

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert!(result.unwrap().is_none());
    }

    // --- e_value_inum != 0 -> InvalidInlineData ---

    #[test]
    fn nonzero_value_inum_is_error() {
        let mut buf = base_buf();
        let data = b"test";
        let offs = place_value(&mut buf, data);
        write_entry(
            &mut buf,
            FIRST_ENTRY,
            SYSTEM_NAME_INDEX,
            b"data",
            offs,
            999, // e_value_inum != 0
            u32::try_from(data.len()).expect("the test fixture value fits in u32"),
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        match result {
            Err(ExtError::InvalidInlineData { inode }) => {
                assert_eq!(inode, TEST_INODE);
            }
            other => panic!("expected InvalidInlineData, got {other:?}"),
        }
    }

    // --- out-of-bounds value -> InvalidInlineData ---

    #[test]
    fn value_out_of_bounds_is_error() {
        let mut buf = base_buf();
        // e_value_offs points beyond the inode
        write_entry(
            &mut buf,
            FIRST_ENTRY,
            SYSTEM_NAME_INDEX,
            b"data",
            250, // will push value_start + size past inode end
            0,
            100,
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        match result {
            Err(ExtError::InvalidInlineData { inode }) => {
                assert_eq!(inode, TEST_INODE);
            }
            other => panic!("expected InvalidInlineData, got {other:?}"),
        }
    }

    #[test]
    fn value_size_exceeds_buffer_is_error() {
        let mut buf = base_buf();
        // Place value_start inside the buffer but value_size overflows.
        // value_start = FIRST_ENTRY + offs. Use offs that puts start
        // near the end, then claim a large size.
        let offs = u16::try_from(INODE_SIZE as usize - FIRST_ENTRY - 4)
            .expect("the test fixture value fits in u16");
        write_entry(
            &mut buf,
            FIRST_ENTRY,
            SYSTEM_NAME_INDEX,
            b"data",
            offs,
            0,
            200, // value_start + 200 > inode_len
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        match result {
            Err(ExtError::InvalidInlineData { inode }) => {
                assert_eq!(inode, TEST_INODE);
            }
            other => panic!("expected InvalidInlineData, got {other:?}"),
        }
    }

    // --- malformed/truncated entry -> InvalidInlineData ---

    #[test]
    fn truncated_entry_header_is_error() {
        let buf = base_buf();
        // Place a non-zero byte at FIRST_ENTRY so it doesn't look
        // like a terminator, but leave no room for a full header
        // by claiming the inode is only slightly larger than the
        // magic offset.
        let short_inode_size: u16 =
            u16::try_from(FIRST_ENTRY + 4).expect("the test fixture value fits in u16");
        let mut short_buf = buf[..short_inode_size as usize].to_vec();
        // Non-zero name_len so it's not a terminator
        short_buf[FIRST_ENTRY] = 5;
        short_buf[FIRST_ENTRY + 1] = 1;

        let result = find_system_data(&short_buf, EXTRA_ISIZE, TEST_INODE);
        match result {
            Err(ExtError::InvalidInlineData { inode }) => {
                assert_eq!(inode, TEST_INODE);
            }
            other => panic!("expected InvalidInlineData, got {other:?}"),
        }
    }

    #[test]
    fn truncated_entry_name_is_error() {
        // Header fits but claimed name length extends past inode end
        let short_inode_size: u16 = u16::try_from(FIRST_ENTRY + ENTRY_HEADER_SIZE + 2)
            .expect("the test fixture value fits in u16");
        let mut buf = vec![0u8; short_inode_size as usize];
        buf[XATTR_START..XATTR_START + 4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        // name_len=10 but only 2 bytes available after header
        buf[FIRST_ENTRY] = 10;
        buf[FIRST_ENTRY + 1] = 1;

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        match result {
            Err(ExtError::InvalidInlineData { inode }) => {
                assert_eq!(inode, TEST_INODE);
            }
            other => panic!("expected InvalidInlineData, got {other:?}"),
        }
    }

    // --- multiple entries with alignment ---

    #[test]
    fn system_data_after_other_entries() {
        let mut buf = base_buf();

        // Entry 1: user.comment (index=1, name="comment", 7 bytes)
        // Entry header: 16 + 7 = 23, aligned to 24
        let val1 = b"first_value!";
        let offs1 = place_value(&mut buf, val1);
        let next = write_entry(
            &mut buf,
            FIRST_ENTRY,
            1,
            b"comment",
            offs1,
            0,
            u32::try_from(val1.len()).expect("the test fixture value fits in u32"),
        );

        // Entry 2: system.data
        let val2 = b"inline overflow";
        let offs2 = place_value(&mut buf, val2);
        write_entry(
            &mut buf,
            next,
            SYSTEM_NAME_INDEX,
            b"data",
            offs2,
            0,
            u32::try_from(val2.len()).expect("the test fixture value fits in u32"),
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert_eq!(result.unwrap().unwrap(), val2);
    }

    #[test]
    fn three_entries_system_data_in_middle() {
        // Use a 512-byte inode to fit three entries + values
        let big_inode: u16 = 512;
        let xattr_start = 128 + EXTRA_ISIZE as usize;
        let first_entry = xattr_start + 4;

        let mut buf = vec![0u8; big_inode as usize];
        buf[xattr_start..xattr_start + 4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());

        // Entry 1: security.selinux (index=6, name="selinux")
        let val1 = b"unconfined_t";
        let v1_start = big_inode as usize - val1.len();
        buf[v1_start..v1_start + val1.len()].copy_from_slice(val1);
        let offs1 =
            u16::try_from(v1_start - first_entry).expect("the test fixture value fits in u16");
        let next = write_entry(
            &mut buf,
            first_entry,
            6,
            b"selinux",
            offs1,
            0,
            u32::try_from(val1.len()).expect("the test fixture value fits in u32"),
        );

        // Entry 2: system.data
        let val2 = b"THE_INLINE_DATA";
        let v2_start = v1_start - val2.len();
        buf[v2_start..v2_start + val2.len()].copy_from_slice(val2);
        let offs2 =
            u16::try_from(v2_start - first_entry).expect("the test fixture value fits in u16");
        let next = write_entry(
            &mut buf,
            next,
            SYSTEM_NAME_INDEX,
            b"data",
            offs2,
            0,
            u32::try_from(val2.len()).expect("the test fixture value fits in u32"),
        );

        // Entry 3: user.tag (index=1, name="tag")
        let val3 = b"important";
        let v3_start = v2_start - val3.len();
        buf[v3_start..v3_start + val3.len()].copy_from_slice(val3);
        let offs3 =
            u16::try_from(v3_start - first_entry).expect("the test fixture value fits in u16");
        let next = write_entry(
            &mut buf,
            next,
            1,
            b"tag",
            offs3,
            0,
            u32::try_from(val3.len()).expect("the test fixture value fits in u32"),
        );

        // Terminate
        buf[next] = 0;
        buf[next + 1] = 0;

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert_eq!(result.unwrap().unwrap(), val2);
    }

    // --- edge: xattr region too small for magic ---

    #[test]
    fn xattr_region_too_small_returns_none() {
        // inode_size barely fits the base + extra, no room for magic
        let tiny_inode: u16 = u16::try_from(128 + EXTRA_ISIZE as usize + 2)
            .expect("the test fixture value fits in u16");
        let buf = vec![0u8; tiny_inode as usize];

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        assert!(result.unwrap().is_none());
    }

    // --- edge: zero-length value ---

    #[test]
    fn zero_length_value() {
        let mut buf = base_buf();
        let _ = write_entry(
            &mut buf,
            FIRST_ENTRY,
            SYSTEM_NAME_INDEX,
            b"data",
            0,
            0,
            0, // zero-length value
        );

        let result = find_system_data(&buf, EXTRA_ISIZE, TEST_INODE);
        let data = result.unwrap().unwrap();
        assert!(data.is_empty());
    }
}
