use zerocopy::byteorder::U32;
use zerocopy::{FromBytes, LittleEndian as LE};

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{Read, Seek, SeekFrom};

/// Number of direct block pointers in the `i_block` array.
const DIRECT_BLOCKS: u32 = 12;

/// Byte offset within `i_block` of the single-indirect pointer.
const SINGLE_INDIRECT_OFF: usize = 48;

/// Byte offset within `i_block` of the double-indirect pointer.
const DOUBLE_INDIRECT_OFF: usize = 52;

/// Byte offset within `i_block` of the triple-indirect pointer.
const TRIPLE_INDIRECT_OFF: usize = 56;

/// Read a little-endian u32 block pointer from a 4-byte slice.
fn read_ptr(buf: &[u8], off: usize) -> u32 {
    U32::<LE>::ref_from_bytes(&buf[off..off + 4])
        .expect("4-byte slice must parse as U32")
        .get()
}

/// Validate a block pointer against the filesystem's block count.
/// Returns `Ok(None)` for pointer value 0 (sparse hole).
/// Returns `Ok(Some(ptr))` for valid non-zero pointers.
/// Returns `Err(BlockOutOfRange)` for out-of-range pointers.
fn validate_ptr(ext: &Ext, ptr: u32) -> Result<Option<u64>> {
    if ptr == 0 {
        return Ok(None);
    }
    let block = u64::from(ptr);
    if block >= ext.blocks_count {
        return Err(ExtError::BlockOutOfRange { block });
    }
    Ok(Some(block))
}

/// Read a block of indirect pointers from disk and return the pointer
/// at the given index.
fn read_indirect_entry<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    indirect_block: u64,
    index: u32,
) -> Result<Option<u64>> {
    let byte_offset = indirect_block * u64::from(ext.block_size) + u64::from(index) * 4;
    fs.seek(SeekFrom::Start(byte_offset))?;

    let mut buf = [0u8; 4];
    fs.read_exact(&mut buf)?;

    let ptr = read_ptr(&buf, 0);
    validate_ptr(ext, ptr)
}

/// Read an entire indirect block from disk and return the pointer
/// at the given index within it.
fn read_indirect_block_entry<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    block_ptr: u32,
    index: u32,
) -> Result<Option<u64>> {
    let Some(block) = validate_ptr(ext, block_ptr)? else {
        return Ok(None);
    };
    read_indirect_entry(ext, fs, block, index)
}

/// Collect all physical data blocks referenced by the indirect block map.
///
/// Appends every non-sparse physical block to `out`, including indirect
/// pointer blocks themselves (they consume allocated space). Sparse holes
/// (pointer value 0) are silently skipped.
pub(crate) fn collect_block_map_blocks_into<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    i_block: &[u8; 60],
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    let n = ext.block_size / 4;

    // Direct blocks [0..12]
    for i in 0..DIRECT_BLOCKS as usize {
        let ptr = read_ptr(i_block, i * 4);
        if let Some(block) = validate_ptr(ext, ptr)? {
            out.push(block);
        }
    }

    // Single indirect
    let si_ptr = read_ptr(i_block, SINGLE_INDIRECT_OFF);
    if let Some(si_block) = validate_ptr(ext, si_ptr)? {
        out.push(si_block);
        collect_indirect_blocks(ext, fs, si_block, out)?;
    }

    // Double indirect
    let di_ptr = read_ptr(i_block, DOUBLE_INDIRECT_OFF);
    if let Some(di_block) = validate_ptr(ext, di_ptr)? {
        out.push(di_block);
        collect_double_indirect_blocks(ext, fs, di_block, n, out)?;
    }

    // Triple indirect
    let ti_ptr = read_ptr(i_block, TRIPLE_INDIRECT_OFF);
    if let Some(ti_block) = validate_ptr(ext, ti_ptr)? {
        out.push(ti_block);
        collect_triple_indirect_blocks(ext, fs, ti_block, n, out)?;
    }

    Ok(())
}

/// Read one indirect block and append each non-zero data pointer to `out`.
fn collect_indirect_blocks<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    indirect_block: u64,
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    let block_size = ext.block_size as usize;
    let byte_offset = indirect_block * u64::from(ext.block_size);
    fs.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = alloc::vec![0u8; block_size];
    fs.read_exact(&mut buf)?;

    let n = block_size / 4;
    for i in 0..n {
        let ptr = read_ptr(&buf, i * 4);
        if let Some(block) = validate_ptr(ext, ptr)? {
            out.push(block);
        }
    }
    Ok(())
}

/// Read one double-indirect block, then collect each child indirect block.
fn collect_double_indirect_blocks<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    dbl_block: u64,
    n: u32,
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    let block_size = ext.block_size as usize;
    let byte_offset = dbl_block * u64::from(ext.block_size);
    fs.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = alloc::vec![0u8; block_size];
    fs.read_exact(&mut buf)?;

    for i in 0..n as usize {
        let ptr = read_ptr(&buf, i * 4);
        if let Some(ind_block) = validate_ptr(ext, ptr)? {
            out.push(ind_block);
            collect_indirect_blocks(ext, fs, ind_block, out)?;
        }
    }
    Ok(())
}

/// Read one triple-indirect block, then collect each child double-indirect block.
fn collect_triple_indirect_blocks<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    tpl_block: u64,
    n: u32,
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    let block_size = ext.block_size as usize;
    let byte_offset = tpl_block * u64::from(ext.block_size);
    fs.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = alloc::vec![0u8; block_size];
    fs.read_exact(&mut buf)?;

    for i in 0..n as usize {
        let ptr = read_ptr(&buf, i * 4);
        if let Some(dbl_block) = validate_ptr(ext, ptr)? {
            out.push(dbl_block);
            collect_double_indirect_blocks(ext, fs, dbl_block, n, out)?;
        }
    }
    Ok(())
}

/// Resolve a logical block number via the indirect block map.
///
/// The `i_block` array contains 15 little-endian u32 pointers:
/// - [0..12]: direct block pointers
/// - [12]: single indirect
/// - [13]: double indirect
/// - [14]: triple indirect
///
/// Returns `Ok(None)` for sparse holes (pointer value 0).
/// Returns `Err(BlockOutOfRange)` for corrupt pointers exceeding
/// `blocks_count`.
pub(crate) fn resolve_block_map<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    i_block: &[u8; 60],
    logical_block: u32,
) -> Result<Option<u64>> {
    let n = ext.block_size / 4;

    if logical_block < DIRECT_BLOCKS {
        let ptr = read_ptr(i_block, (logical_block as usize) * 4);
        return validate_ptr(ext, ptr);
    }

    let remaining = logical_block - DIRECT_BLOCKS;

    // Single indirect: blocks [12 .. 12+N)
    if remaining < n {
        let indirect_ptr = read_ptr(i_block, SINGLE_INDIRECT_OFF);
        return read_indirect_block_entry(ext, fs, indirect_ptr, remaining);
    }

    let remaining = remaining - n;

    // Double indirect: blocks [12+N .. 12+N+N^2)
    let n_squared = n.saturating_mul(n);
    if remaining < n_squared {
        let dbl_ptr = read_ptr(i_block, DOUBLE_INDIRECT_OFF);
        let Some(dbl_block) = validate_ptr(ext, dbl_ptr)? else {
            return Ok(None);
        };

        let first_idx = remaining / n;
        let second_idx = remaining % n;

        let ind_block = read_indirect_entry(ext, fs, dbl_block, first_idx)?;
        let Some(ind_block) = ind_block else {
            return Ok(None);
        };

        return read_indirect_entry(ext, fs, ind_block, second_idx);
    }

    let remaining = remaining - n_squared;

    // Triple indirect: blocks [12+N+N^2 .. 12+N+N^2+N^3)
    let n_cubed = n_squared.saturating_mul(n);
    if remaining < n_cubed {
        let tpl_ptr = read_ptr(i_block, TRIPLE_INDIRECT_OFF);
        let Some(tpl_block) = validate_ptr(ext, tpl_ptr)? else {
            return Ok(None);
        };

        let first_idx = remaining / n_squared;
        let sub_remaining = remaining % n_squared;
        let second_idx = sub_remaining / n;
        let third_idx = sub_remaining % n;

        let dbl_block = read_indirect_entry(ext, fs, tpl_block, first_idx)?;
        let Some(dbl_block) = dbl_block else {
            return Ok(None);
        };

        let ind_block = read_indirect_entry(ext, fs, dbl_block, second_idx)?;
        let Some(ind_block) = ind_block else {
            return Ok(None);
        };

        return read_indirect_entry(ext, fs, ind_block, third_idx);
    }

    // Beyond addressable range -- treat as hole
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Ext struct for testing (only `block_size` and `blocks_count`
    /// matter for block map resolution).
    fn test_ext() -> Ext {
        Ext {
            inodes_count: 100,
            blocks_count: 10000,
            block_size: 4096,
            group_count: 1,
            inodes_per_group: 100,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                4096,
                8192,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 8192,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 8192,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat: crate::feature_flags::RoCompatFeatures::empty(),
            compat: crate::feature_flags::CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::FscryptKeystore::default(),
        }
    }

    /// Build an `i_block` array with direct pointers set.
    fn make_direct_iblock(ptrs: &[u32; 15]) -> [u8; 60] {
        let mut buf = [0u8; 60];
        for (i, &ptr) in ptrs.iter().enumerate() {
            let off = i * 4;
            buf[off..off + 4].copy_from_slice(&ptr.to_le_bytes());
        }
        buf
    }

    #[test]
    fn direct_block_resolution() {
        let ext = test_ext();
        let ptrs = [100, 101, 102, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let iblock = make_direct_iblock(&ptrs);
        let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

        // Block 0 -> 100
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 0).expect("should not error");
        assert_eq!(result, Some(100));

        // Block 2 -> 102
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 2).expect("should not error");
        assert_eq!(result, Some(102));

        // Block 3 -> None (hole, pointer is 0)
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 3).expect("should not error");
        assert_eq!(result, None);

        // Block 4 -> 104
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 4).expect("should not error");
        assert_eq!(result, Some(104));
    }

    #[test]
    fn direct_block_out_of_range() {
        let ext = test_ext(); // blocks_count = 10000
        let ptrs = [99999, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let iblock = make_direct_iblock(&ptrs);
        let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

        let err = resolve_block_map(&ext, &mut cursor, &iblock, 0)
            .expect_err("should fail with block out of range");
        match err {
            ExtError::BlockOutOfRange { block } => {
                assert_eq!(block, 99999);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn single_indirect_resolution() {
        let ext = test_ext(); // block_size = 4096, N = 1024
        // i_block[12] (single indirect) = block 50
        let mut ptrs = [0u32; 15];
        ptrs[12] = 50;
        let iblock = make_direct_iblock(&ptrs);

        // Build disk image: at block 50, put indirect pointers
        let indirect_offset = 50u64 * 4096;
        let disk_size =
            usize::try_from(indirect_offset + 4096).expect("the test fixture value fits in usize");
        let mut disk = vec![0u8; disk_size];

        // Entry 0 in indirect block -> physical block 200
        let ib = &mut disk
            [usize::try_from(indirect_offset).expect("the test fixture value fits in usize")..];
        ib[0..4].copy_from_slice(&200u32.to_le_bytes());
        // Entry 5 -> physical block 300
        ib[20..24].copy_from_slice(&300u32.to_le_bytes());

        let mut cursor = fsmnt_testkit::Cursor::new(disk);

        // Logical block 12 -> indirect entry 0 -> 200
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 12).expect("should not error");
        assert_eq!(result, Some(200));

        // Logical block 17 -> indirect entry 5 -> 300
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 17).expect("should not error");
        assert_eq!(result, Some(300));

        // Logical block 13 -> indirect entry 1 -> 0 (hole)
        let result = resolve_block_map(&ext, &mut cursor, &iblock, 13).expect("should not error");
        assert_eq!(result, None);
    }

    #[test]
    fn single_indirect_null_pointer() {
        let ext = test_ext();
        // i_block[12] = 0 (no indirect block allocated)
        let ptrs = [0u32; 15];
        let iblock = make_direct_iblock(&ptrs);
        let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

        let result = resolve_block_map(&ext, &mut cursor, &iblock, 12).expect("should not error");
        assert_eq!(result, None);
    }

    #[test]
    fn double_indirect_resolution() {
        let ext = test_ext(); // N = 1024
        let mut ptrs = [0u32; 15];
        ptrs[13] = 60; // double indirect block at block 60
        let iblock = make_direct_iblock(&ptrs);

        // logical block 12 + 1024 = 1036 is the first double-indirect block
        // remaining = 1036 - 12 - 1024 = 0
        // first_idx = 0 / 1024 = 0, second_idx = 0 % 1024 = 0

        let dbl_offset = 60u64 * 4096;
        let ind_block_num = 70u32;
        let ind_offset = u64::from(ind_block_num) * 4096;
        let disk_size =
            usize::try_from(ind_offset + 4096).expect("the test fixture value fits in usize");
        let mut disk = vec![0u8; disk_size];

        // Double indirect block: entry 0 -> indirect block 70
        let dbl =
            &mut disk[usize::try_from(dbl_offset).expect("the test fixture value fits in usize")..];
        dbl[0..4].copy_from_slice(&ind_block_num.to_le_bytes());

        // Indirect block 70: entry 0 -> data block 500
        let ind =
            &mut disk[usize::try_from(ind_offset).expect("the test fixture value fits in usize")..];
        ind[0..4].copy_from_slice(&500u32.to_le_bytes());

        let mut cursor = fsmnt_testkit::Cursor::new(disk);

        let result = resolve_block_map(&ext, &mut cursor, &iblock, 1036).expect("should not error");
        assert_eq!(result, Some(500));
    }

    #[test]
    fn beyond_addressable_range_returns_none() {
        let ext = test_ext();
        let ptrs = [0u32; 15];
        let iblock = make_direct_iblock(&ptrs);
        let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

        // A very large logical block that exceeds triple indirect range
        let result =
            resolve_block_map(&ext, &mut cursor, &iblock, u32::MAX).expect("should not error");
        assert_eq!(result, None);
    }
}
