use super::{
    CurrentDirInode, DirAppendSlot, DirRemoveSlot, Ext, ExtError, MutatorError, MutatorResult,
    Read, Seek,
};

pub(super) fn resolve_dir_logical_block<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: &CurrentDirInode,
    logical_block: u32,
) -> MutatorResult<u64> {
    let physical = if inode.flags.contains(crate::inode::InodeFlags::EXTENTS_FL) {
        let extent = crate::extent::resolve_extent(
            ext,
            fs,
            inode.number,
            inode.generation,
            &inode.i_block,
            logical_block,
        )?
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
            block: u64::from(logical_block),
        }))?;
        if extent.uninitialized {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            }));
        }
        let blocks_into =
            logical_block
                .checked_sub(extent.logical_block)
                .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: u64::from(logical_block),
                }))?;
        extent
            .physical_block
            .checked_add(u64::from(blocks_into))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: extent.physical_block,
            }))?
    } else {
        crate::block_map::resolve_block_map(ext, fs, &inode.i_block, logical_block)?.ok_or(
            MutatorError::Ext(ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            }),
        )?
    };

    if physical >= ext.blocks_count {
        return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
            block: physical,
        }));
    }
    Ok(physical)
}

pub(super) fn find_dir_append_slot(
    block: &[u8],
    has_filetype: bool,
    parent_inum: u32,
    required_len: usize,
) -> MutatorResult<Option<DirAppendSlot>> {
    let usable_end = directory_entry_region_end(block);
    let mut offset = 0usize;
    let mut last_real: Option<(usize, usize, usize, u16)> = None;

    while offset < usable_end {
        if offset + 8 > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
        if rec_len < 8 || rec_len % 4 != 0 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let rec_len_usize = usize::from(rec_len);
        let next_offset = offset
            .checked_add(rec_len_usize)
            .ok_or(invalid_dir_entry(parent_inum, offset))?;
        if next_offset > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().unwrap(),
            ))
        };
        if name_len > rec_len_usize - 8 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        if inode != 0 {
            let min_len =
                aligned_dir_entry_len(name_len).ok_or(invalid_dir_entry(parent_inum, offset))?;
            if min_len > rec_len_usize {
                return Err(invalid_dir_entry(parent_inum, offset));
            }
            last_real = Some((offset, next_offset, min_len, rec_len));
        }

        offset = next_offset;
    }

    let Some((last_offset, last_next, min_len, rec_len)) = last_real else {
        return Ok(None);
    };
    if last_next != usable_end {
        return Ok(None);
    }

    let slack = usize::from(rec_len)
        .checked_sub(min_len)
        .ok_or(invalid_dir_entry(parent_inum, last_offset))?;
    if slack < required_len {
        return Ok(None);
    }

    Ok(Some(DirAppendSlot {
        last_entry_offset: last_offset,
        shrunk_last_rec_len: u16::try_from(min_len)
            .map_err(|_| invalid_dir_entry(parent_inum, last_offset))?,
        new_entry_offset: last_offset + min_len,
        new_entry_rec_len: u16::try_from(slack)
            .map_err(|_| invalid_dir_entry(parent_inum, last_offset))?,
    }))
}

pub(super) fn apply_dir_append_slot(
    block: &mut [u8],
    slot: DirAppendSlot,
    child_inum: u32,
    name: &[u8],
    file_type: u8,
    has_filetype: bool,
    parent_inum: u32,
) -> MutatorResult<()> {
    let new_entry_end = slot.new_entry_offset + usize::from(slot.new_entry_rec_len);
    let name_end = slot.new_entry_offset + 8 + name.len();
    if slot.last_entry_offset + 8 > block.len()
        || new_entry_end > block.len()
        || name_end > new_entry_end
    {
        return Err(invalid_dir_entry(parent_inum, slot.last_entry_offset));
    }

    block[slot.last_entry_offset + 4..slot.last_entry_offset + 6]
        .copy_from_slice(&slot.shrunk_last_rec_len.to_le_bytes());

    block[slot.new_entry_offset..new_entry_end].fill(0);
    block[slot.new_entry_offset..slot.new_entry_offset + 4]
        .copy_from_slice(&child_inum.to_le_bytes());
    block[slot.new_entry_offset + 4..slot.new_entry_offset + 6]
        .copy_from_slice(&slot.new_entry_rec_len.to_le_bytes());
    if has_filetype {
        block[slot.new_entry_offset + 6] = u8::try_from(name.len())
            .map_err(|_| invalid_dir_entry(parent_inum, slot.new_entry_offset))?;
        block[slot.new_entry_offset + 7] = file_type;
    } else {
        block[slot.new_entry_offset + 6..slot.new_entry_offset + 8].copy_from_slice(
            &u16::try_from(name.len())
                .map_err(|_| invalid_dir_entry(parent_inum, slot.new_entry_offset))?
                .to_le_bytes(),
        );
    }
    block[slot.new_entry_offset + 8..name_end].copy_from_slice(name);
    Ok(())
}

pub(super) fn find_dir_remove_slot(
    block: &[u8],
    has_filetype: bool,
    parent_inum: u32,
    child_inum: u32,
    name: &[u8],
) -> MutatorResult<Option<DirRemoveSlot>> {
    let usable_end = directory_entry_region_end(block);
    let mut offset = 0usize;
    let mut prev: Option<(usize, u16)> = None;

    while offset < usable_end {
        if offset + 8 > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
        if rec_len < 8 || rec_len % 4 != 0 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let rec_len_usize = usize::from(rec_len);
        let next_offset = offset
            .checked_add(rec_len_usize)
            .ok_or(invalid_dir_entry(parent_inum, offset))?;
        if next_offset > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().unwrap(),
            ))
        };
        if name_len > rec_len_usize - 8 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let name_end = offset + 8 + name_len;
        if inode == child_inum && &block[offset + 8..name_end] == name {
            let Some((prev_offset, _)) = prev else {
                if offset == 0 {
                    return Ok(Some(DirRemoveSlot::ClearCurrentInode {
                        current_offset: offset,
                    }));
                }
                return Err(invalid_dir_entry(parent_inum, offset));
            };
            return Ok(Some(DirRemoveSlot::MergeIntoPrev {
                prev_offset,
                current_offset: offset,
                current_rec_len: rec_len,
            }));
        }

        prev = Some((offset, rec_len));
        offset = next_offset;
    }

    Ok(None)
}

pub(super) fn apply_dir_remove_slot(
    block: &mut [u8],
    slot: DirRemoveSlot,
    parent_inum: u32,
) -> MutatorResult<()> {
    match slot {
        DirRemoveSlot::MergeIntoPrev {
            prev_offset,
            current_offset,
            current_rec_len,
        } => {
            if prev_offset + 6 > block.len()
                || current_offset + usize::from(current_rec_len) > block.len()
            {
                return Err(invalid_dir_entry(parent_inum, prev_offset));
            }
            let prev_rec_len =
                u16::from_le_bytes(block[prev_offset + 4..prev_offset + 6].try_into().unwrap());
            if prev_rec_len < 8
                || prev_rec_len % 4 != 0
                || prev_offset + usize::from(prev_rec_len) != current_offset
            {
                return Err(invalid_dir_entry(parent_inum, prev_offset));
            }
            let merged_prev_rec_len = prev_rec_len
                .checked_add(current_rec_len)
                .ok_or(invalid_dir_entry(parent_inum, prev_offset))?;
            block[prev_offset + 4..prev_offset + 6]
                .copy_from_slice(&merged_prev_rec_len.to_le_bytes());
        }
        DirRemoveSlot::ClearCurrentInode { current_offset } => {
            if current_offset + 4 > block.len() {
                return Err(invalid_dir_entry(parent_inum, current_offset));
            }
            block[current_offset..current_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        }
    }
    Ok(())
}

pub(super) fn validate_dir_tail_checksum(
    seed: Option<u32>,
    parent_inum: u32,
    parent_generation: u32,
    block: &[u8],
) -> MutatorResult<()> {
    let Some(seed) = seed else {
        return Ok(());
    };
    let Some(tail_offset) = directory_tail_offset(block) else {
        return Ok(());
    };

    if crate::checksum::verify_dir_block(seed, parent_inum, parent_generation, block)
        == crate::checksum::ChecksumState::Invalid
    {
        return Err(invalid_dir_entry(parent_inum, tail_offset));
    }
    Ok(())
}

pub(super) fn refresh_dir_tail_checksum(
    seed: Option<u32>,
    parent_inum: u32,
    parent_generation: u32,
    block: &mut [u8],
) {
    let Some(seed) = seed else {
        return;
    };
    let Some(tail_offset) = directory_tail_offset(block) else {
        return;
    };

    let crc = crate::checksum::ext4_crc32c(seed, &parent_inum.to_le_bytes());
    let crc = crate::checksum::ext4_crc32c(crc, &parent_generation.to_le_bytes());
    let crc = crate::checksum::ext4_crc32c(crc, &block[..tail_offset]);
    block[tail_offset + 8..tail_offset + 12].copy_from_slice(&crc.to_le_bytes());
}

pub(super) fn aligned_dir_entry_len(name_len: usize) -> Option<usize> {
    8usize
        .checked_add(name_len)
        .and_then(|len| len.checked_add(3))
        .map(|len| len & !3)
}

pub(super) fn directory_entry_region_end(block: &[u8]) -> usize {
    directory_tail_offset(block).unwrap_or(block.len())
}

pub(super) fn directory_tail_offset(block: &[u8]) -> Option<usize> {
    if block.len() >= 12 {
        let tail_offset = block.len() - 12;
        let tail = &block[tail_offset..];
        let inode = u32::from_le_bytes(tail[0..4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(tail[4..6].try_into().unwrap());
        if inode == 0 && rec_len == 12 && tail[6] == 0 && tail[7] == 0xDE {
            return Some(tail_offset);
        }
    }
    None
}

pub(super) fn invalid_dir_entry(parent_inum: u32, offset: usize) -> MutatorError {
    MutatorError::Ext(ExtError::InvalidDirectoryEntry {
        inode: parent_inum,
        offset: offset as u64,
    })
}
