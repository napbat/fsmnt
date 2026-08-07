//! Cross-device, tree-identity, and checksum-item validation.

use alloc::vec::Vec;

use crate::item::{
    EXTENT_CHECKSUM_KEY, EXTENT_CHECKSUM_OBJECT_ID, RootItem, valid_filesystem_tree_id,
};
use crate::tree::TreeItem;
use crate::{BtrfsError, BtrfsSuperblock, DiskKey, Result};

use super::Device;

pub(super) fn should_replace_root(current: Option<&RootItem>, candidate: &RootItem) -> bool {
    current.is_none_or(|root| candidate.key_offset > root.key_offset)
}

pub(super) fn should_select_primary(
    current: &BtrfsSuperblock,
    candidate: &BtrfsSuperblock,
) -> bool {
    match (current.is_seeding(), candidate.is_seeding()) {
        (true, false) => true,
        (false, true) => false,
        _ => candidate.generation() > current.generation(),
    }
}

pub(super) fn validate_devices<R>(primary: &Device<R>, additional: &[Device<R>]) -> Result<()> {
    let devices = || core::iter::once(primary).chain(additional.iter());
    let mut identities = Vec::with_capacity(additional.len().saturating_add(1));
    for device in devices() {
        let superblock = &device.superblock;
        if superblock.sector_size() != primary.superblock.sector_size()
            || superblock.node_size() != primary.superblock.node_size()
            || superblock.checksum_type() != primary.superblock.checksum_type()
            || (superblock.fsid() != primary.superblock.fsid() && !superblock.is_seeding())
        {
            return Err(BtrfsError::ForeignDevice);
        }

        let group_members = devices()
            .filter(|candidate| candidate.superblock.fsid() == superblock.fsid())
            .count();
        let group_members_u64 =
            u64::try_from(group_members).map_err(|_| BtrfsError::IntegerOverflow)?;
        if group_members_u64 > superblock.num_devices() {
            return Err(BtrfsError::DeviceCountMismatch {
                expected: superblock.num_devices(),
                actual: group_members,
            });
        }
        if devices().any(|candidate| {
            candidate.superblock.fsid() == superblock.fsid()
                && candidate.superblock.num_devices() != superblock.num_devices()
        }) {
            return Err(BtrfsError::ForeignDevice);
        }

        let identity = (
            *superblock.fsid(),
            superblock.device_id(),
            *superblock.device_uuid(),
        );
        if identities.iter().any(|(fsid, device_id, uuid)| {
            *uuid == identity.2 || (*fsid == identity.0 && *device_id == identity.1)
        }) {
            return Err(BtrfsError::DuplicateDevice {
                device_id: identity.1,
            });
        }
        identities.push(identity);
    }
    Ok(())
}

pub(super) fn validate_tree_identity(
    expected_owner: u64,
    expected_generation: Option<u64>,
    expected_first_key: Option<DiskKey>,
    owner: u64,
    generation: u64,
    first_key: Option<DiskKey>,
    logical: u64,
) -> Result<()> {
    let owner_matches = if expected_first_key.is_none() {
        owner == expected_owner
    } else if valid_filesystem_tree_id(expected_owner) {
        valid_filesystem_tree_id(owner)
    } else {
        owner == expected_owner
    };
    if !owner_matches
        || expected_generation.is_some_and(|expected| expected != generation)
        || expected_first_key.is_some_and(|expected| Some(expected) != first_key)
    {
        return Err(BtrfsError::MalformedTreeBlock { logical });
    }
    Ok(())
}

pub(super) fn validate_checksum_items(
    items: &[TreeItem],
    sector_size: u32,
    checksum_size: usize,
) -> Result<()> {
    if sector_size == 0 || checksum_size == 0 {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let mut previous_end = None;
    for item in items {
        validate_checksum_item(item, sector_size, checksum_size)?;
        let checksum_count = item.data.len() / checksum_size;
        let covered_bytes = u64::try_from(checksum_count)
            .map_err(|_| BtrfsError::IntegerOverflow)?
            .checked_mul(u64::from(sector_size))
            .ok_or(BtrfsError::IntegerOverflow)?;
        let item_end = item
            .key
            .offset
            .checked_add(covered_bytes)
            .ok_or_else(|| malformed_item(item.key))?;
        if previous_end.is_some_and(|end| end > item.key.offset) {
            return Err(malformed_item(item.key));
        }
        previous_end = Some(item_end);
    }
    Ok(())
}

pub(super) fn validate_checksum_item(
    item: &TreeItem,
    sector_size: u32,
    checksum_size: usize,
) -> Result<()> {
    if sector_size == 0
        || checksum_size == 0
        || item.key.object_id != EXTENT_CHECKSUM_OBJECT_ID
        || item.key.item_type != EXTENT_CHECKSUM_KEY
        || !item.key.offset.is_multiple_of(u64::from(sector_size))
        || item.data.is_empty()
        || !item.data.len().is_multiple_of(checksum_size)
    {
        return Err(malformed_item(item.key));
    }
    Ok(())
}

pub(super) fn committed_checksum(
    items: &[TreeItem],
    logical: u64,
    sector_size: u32,
    checksum_size: usize,
) -> Result<&[u8]> {
    let item = items
        .iter()
        .rev()
        .find(|item| item.key.offset <= logical)
        .ok_or(BtrfsError::DataChecksumMissing { logical })?;
    let delta = logical - item.key.offset;
    if !delta.is_multiple_of(u64::from(sector_size)) {
        return Err(BtrfsError::DataChecksumMissing { logical });
    }
    let index =
        usize::try_from(delta / u64::from(sector_size)).map_err(|_| BtrfsError::IntegerOverflow)?;
    let start = index
        .checked_mul(checksum_size)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let end = start
        .checked_add(checksum_size)
        .ok_or(BtrfsError::IntegerOverflow)?;
    item.data
        .get(start..end)
        .ok_or(BtrfsError::DataChecksumMissing { logical })
}

pub(super) const fn malformed_item(key: DiskKey) -> BtrfsError {
    BtrfsError::MalformedItem {
        object_id: key.object_id,
        item_type: key.item_type,
        offset: key.offset,
    }
}
