//! Data-checksum lookup across legacy and extent-tree-v2 checksum roots.

use fsmnt_parser_core::io::{Read, Seek};

use super::Btrfs;
use super::validation::{committed_checksum, validate_checksum_items};
use crate::item::{CHECKSUM_TREE_OBJECT_ID, EXTENT_CHECKSUM_KEY, EXTENT_CHECKSUM_OBJECT_ID};
use crate::superblock::EXTENT_TREE_V2_INCOMPAT;
use crate::tree::TreeRoot;
use crate::{BtrfsError, DiskKey, Result};

impl<R: Read + Seek> Btrfs<R> {
    pub(crate) fn verify_data_checksums(&mut self, mut logical: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let sector_size = usize::try_from(self.superblock().sector_size())
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        if !logical.is_multiple_of(u64::from(self.superblock().sector_size()))
            || !data.len().is_multiple_of(sector_size)
        {
            return Err(BtrfsError::InvalidFileExtentRange);
        }

        let extent_tree_v2 = self.superblock().incompat_flags() & EXTENT_TREE_V2_INCOMPAT != 0;
        let mut remaining = data;
        while !remaining.is_empty() {
            let scope = self.global_roots.checksum_scope(logical)?;
            let requested =
                u64::try_from(remaining.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
            let segment_len = usize::try_from(scope.remaining.min(requested))
                .map_err(|_| BtrfsError::IntegerOverflow)?;
            if segment_len == 0 || !segment_len.is_multiple_of(sector_size) {
                return Err(BtrfsError::InvalidFileExtentRange);
            }
            let checksum_root = if extent_tree_v2 {
                self.lookup_tree_root_exact(CHECKSUM_TREE_OBJECT_ID, scope.global_root_id)?
            } else {
                self.lookup_tree_root(CHECKSUM_TREE_OBJECT_ID)?
            };
            self.verify_data_checksums_in_root(checksum_root, logical, &remaining[..segment_len])?;
            let consumed = u64::try_from(segment_len).map_err(|_| BtrfsError::IntegerOverflow)?;
            logical = logical
                .checked_add(consumed)
                .ok_or(BtrfsError::IntegerOverflow)?;
            remaining = &remaining[segment_len..];
        }
        Ok(())
    }

    fn verify_data_checksums_in_root(
        &mut self,
        checksum_root: TreeRoot,
        logical: u64,
        data: &[u8],
    ) -> Result<()> {
        let sector_size = usize::try_from(self.superblock().sector_size())
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        let checksum_type = self.superblock().checksum_type();
        let checksum_size = checksum_type.size();
        let last_byte = logical
            .checked_add(u64::try_from(data.len()).map_err(|_| BtrfsError::IntegerOverflow)?)
            .and_then(|end| end.checked_sub(1))
            .ok_or(BtrfsError::IntegerOverflow)?;
        let start_key = DiskKey {
            object_id: EXTENT_CHECKSUM_OBJECT_ID,
            item_type: EXTENT_CHECKSUM_KEY,
            offset: logical,
        };
        let end_key = DiskKey {
            object_id: EXTENT_CHECKSUM_OBJECT_ID,
            item_type: EXTENT_CHECKSUM_KEY,
            offset: last_byte,
        };
        let predecessor = self
            .find_predecessor(checksum_root, start_key)?
            .filter(|item| {
                item.key.object_id == EXTENT_CHECKSUM_OBJECT_ID
                    && item.key.item_type == EXTENT_CHECKSUM_KEY
            });
        let checksum_items = if let Some(predecessor) = predecessor {
            let mut items = self.collect_items_raw(checksum_root, predecessor.key, end_key)?;
            if items.first().is_none_or(|item| item.key != predecessor.key) {
                items.insert(0, predecessor);
            }
            items
        } else {
            alloc::vec::Vec::new()
        };
        if !checksum_items.is_empty() {
            validate_checksum_items(
                &checksum_items,
                self.superblock().sector_size(),
                checksum_size,
            )?;
        }

        for (sector_index, sector) in data.chunks_exact(sector_size).enumerate() {
            let sector_delta = sector_index
                .checked_mul(sector_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let sector_logical = logical
                .checked_add(u64::try_from(sector_delta).map_err(|_| BtrfsError::IntegerOverflow)?)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let logged = self.log_overlay.checksum(
                sector_logical,
                self.superblock().sector_size(),
                checksum_size,
            )?;
            let expected = if let Some(logged) = logged {
                logged
            } else {
                committed_checksum(
                    &checksum_items,
                    sector_logical,
                    self.superblock().sector_size(),
                    checksum_size,
                )?
            };
            if !checksum_type.verify(expected, sector) {
                return Err(BtrfsError::InvalidChecksum {
                    structure: "data sector",
                    logical: sector_logical,
                });
            }
        }
        Ok(())
    }
}
