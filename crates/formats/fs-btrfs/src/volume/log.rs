//! Read-only projection of fsync tree-log records over committed trees.

use alloc::vec::Vec;

use crate::item::{
    BtrfsInode, DIR_INDEX_KEY, DIR_ITEM_KEY, DIR_LOG_INDEX_KEY, DIR_LOG_ITEM_KEY,
    EXTENT_CHECKSUM_KEY, EXTENT_DATA_KEY, FileExtent, INODE_ITEM_KEY, ROOT_ITEM_KEY, RootItem,
    TREE_LOG_OBJECT_ID, parse_directory_entries, valid_filesystem_tree_id, valid_inode_object_id,
};
use crate::tree::{TreeItem, TreeRoot};
use crate::{BtrfsError, DiskKey, Result};
use fsmnt_parser_core::io::{Read, Seek};

use super::Btrfs;
use super::validation::{malformed_item, validate_checksum_item};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthoritativeRange {
    object_id: u64,
    item_type: u8,
    start: u64,
    end: u64,
}

impl AuthoritativeRange {
    const fn contains(self, key: DiskKey) -> bool {
        key.object_id == self.object_id
            && key.item_type == self.item_type
            && key.offset >= self.start
            && key.offset <= self.end
    }
}

#[derive(Default)]
struct LoggedTree {
    tree_id: u64,
    items: Vec<TreeItem>,
    authoritative_ranges: Vec<AuthoritativeRange>,
}

impl LoggedTree {
    fn replaces(&self, key: DiskKey) -> bool {
        self.items
            .binary_search_by_key(&key, |item| item.key)
            .is_ok()
            || self
                .authoritative_ranges
                .iter()
                .any(|range| range.contains(key))
    }
}

/// Validated records from every per-subvolume tree referenced by the log-root tree.
#[derive(Default)]
pub(super) struct LogOverlay {
    trees: Vec<LoggedTree>,
    checksum_items: Vec<TreeItem>,
}

impl LogOverlay {
    pub(super) fn directory_index_changed(&self, tree_id: u64, object_id: u64) -> bool {
        let Some(tree) = self
            .trees
            .binary_search_by_key(&tree_id, |tree| tree.tree_id)
            .ok()
            .and_then(|index| self.trees.get(index))
        else {
            return false;
        };
        if tree
            .authoritative_ranges
            .iter()
            .any(|range| range.object_id == object_id && range.item_type == DIR_INDEX_KEY)
        {
            return true;
        }
        let start = DiskKey::range_start(object_id, DIR_INDEX_KEY);
        let end = DiskKey::range_end(object_id, DIR_INDEX_KEY);
        let first = tree.items.partition_point(|item| item.key < start);
        tree.items.get(first).is_some_and(|item| item.key <= end)
    }

    pub(super) fn overlay_items(
        &self,
        tree_id: u64,
        start: DiskKey,
        end: DiskKey,
        mut committed: Vec<TreeItem>,
    ) -> Result<Vec<TreeItem>> {
        let Some(tree) = self
            .trees
            .binary_search_by_key(&tree_id, |tree| tree.tree_id)
            .ok()
            .and_then(|index| self.trees.get(index))
        else {
            return Ok(committed);
        };

        committed.retain(|item| !tree.replaces(item.key));
        committed.extend(
            tree.items
                .iter()
                .filter(|item| item.key >= start && item.key <= end)
                .cloned(),
        );
        committed.sort_unstable_by_key(|item| item.key);
        if let Some(duplicate) = committed
            .windows(2)
            .find(|items| items[0].key == items[1].key)
            .map(|items| items[1].key)
        {
            return Err(malformed_item(duplicate));
        }
        Ok(committed)
    }

    pub(super) fn logged_extents(
        &self,
        tree_id: u64,
        object_id: u64,
        request_start: u64,
        request_end: u64,
    ) -> Vec<TreeItem> {
        let Some(tree) = self
            .trees
            .binary_search_by_key(&tree_id, |tree| tree.tree_id)
            .ok()
            .and_then(|index| self.trees.get(index))
        else {
            return Vec::new();
        };

        let mut predecessor = None;
        let mut items = Vec::new();
        for item in tree
            .items
            .iter()
            .filter(|item| item.key.object_id == object_id && item.key.item_type == EXTENT_DATA_KEY)
        {
            if item.key.offset <= request_start {
                predecessor = Some(item);
            }
            if item.key.offset >= request_start && item.key.offset <= request_end {
                items.push(item.clone());
            }
        }
        if let Some(predecessor) = predecessor
            && items.first().is_none_or(|item| item.key != predecessor.key)
        {
            items.insert(0, predecessor.clone());
        }
        items
    }

    pub(super) fn checksum(
        &self,
        logical: u64,
        sector_size: u32,
        checksum_size: usize,
    ) -> Result<Option<&[u8]>> {
        let mut found = None;
        for item in &self.checksum_items {
            let sector_size_u64 = u64::from(sector_size);
            let checksum_count = item.data.len() / checksum_size;
            let covered_bytes = u64::try_from(checksum_count)
                .map_err(|_| BtrfsError::IntegerOverflow)?
                .checked_mul(sector_size_u64)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let end = item
                .key
                .offset
                .checked_add(covered_bytes)
                .ok_or_else(|| malformed_item(item.key))?;
            if logical < item.key.offset || logical >= end {
                continue;
            }
            let delta = logical - item.key.offset;
            if !delta.is_multiple_of(sector_size_u64) {
                return Err(malformed_item(item.key));
            }
            let index = usize::try_from(delta / sector_size_u64)
                .map_err(|_| BtrfsError::IntegerOverflow)?;
            let start = index
                .checked_mul(checksum_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let end = start
                .checked_add(checksum_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let checksum = item
                .data
                .get(start..end)
                .ok_or_else(|| malformed_item(item.key))?;
            if found.is_some_and(|previous| previous != checksum) {
                return Err(BtrfsError::InvalidChecksum {
                    structure: "tree-log data checksum",
                    logical,
                });
            }
            found = Some(checksum);
        }
        Ok(found)
    }

    fn add_tree(
        &mut self,
        tree_id: u64,
        raw_items: Vec<TreeItem>,
        sector_size: u32,
        checksum_size: usize,
        super_generation: u64,
    ) -> Result<()> {
        let mut tree = LoggedTree {
            tree_id,
            ..LoggedTree::default()
        };
        for item in raw_items {
            match item.key.item_type {
                DIR_LOG_ITEM_KEY | DIR_LOG_INDEX_KEY => {
                    tree.authoritative_ranges.push(parse_range(&item)?);
                }
                EXTENT_CHECKSUM_KEY => {
                    validate_checksum_item(&item, sector_size, checksum_size)?;
                    self.checksum_items.push(item);
                }
                INODE_ITEM_KEY => {
                    BtrfsInode::parse(item.key, &item.data, super_generation)?;
                    tree.items.push(item);
                }
                DIR_ITEM_KEY | DIR_INDEX_KEY => {
                    parse_directory_entries(item.key, &item.data)?;
                    tree.items.push(item);
                }
                EXTENT_DATA_KEY => {
                    FileExtent::parse(item.key, &item.data, sector_size)?;
                    tree.items.push(item);
                }
                _ => tree.items.push(item),
            }
        }
        tree.items.sort_unstable_by_key(|item| item.key);
        if let Some(duplicate) = tree
            .items
            .windows(2)
            .find(|items| items[0].key == items[1].key)
            .map(|items| items[1].key)
        {
            return Err(malformed_item(duplicate));
        }
        normalize_ranges(&mut tree.authoritative_ranges);
        self.trees.push(tree);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.trees.sort_unstable_by_key(|tree| tree.tree_id);
        if let Some(tree_id) = self
            .trees
            .windows(2)
            .find(|trees| trees[0].tree_id == trees[1].tree_id)
            .map(|trees| trees[1].tree_id)
        {
            return Err(malformed_item(DiskKey {
                object_id: TREE_LOG_OBJECT_ID,
                item_type: ROOT_ITEM_KEY,
                offset: tree_id,
            }));
        }
        self.checksum_items.sort_unstable_by_key(|item| item.key);
        Ok(())
    }
}

impl<R: Read + Seek> Btrfs<R> {
    pub(super) fn read_log_overlay(&mut self) -> Result<LogOverlay> {
        let Some(logical) = self.superblock().log_root() else {
            return Ok(LogOverlay::default());
        };
        let expected_generation = self
            .active_generation()
            .checked_add(1)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let log_root = TreeRoot {
            tree_id: TREE_LOG_OBJECT_ID,
            logical,
            level: self.superblock().log_root_level(),
            expected_generation: Some(expected_generation),
        };
        let root_items = self.collect_items_raw(
            log_root,
            DiskKey {
                object_id: 0,
                item_type: 0,
                offset: 0,
            },
            DiskKey {
                object_id: u64::MAX,
                item_type: u8::MAX,
                offset: u64::MAX,
            },
        )?;
        let sector_size = self.superblock().sector_size();
        let checksum_size = self.superblock().checksum_type().size();
        let super_generation = self.active_generation();
        let mut overlay = LogOverlay::default();
        for item in root_items {
            if item.key.object_id != TREE_LOG_OBJECT_ID
                || item.key.item_type != ROOT_ITEM_KEY
                || !valid_filesystem_tree_id(item.key.offset)
            {
                return Err(malformed_item(item.key));
            }
            let root_item = RootItem::parse(item.key, &item.data, sector_size, super_generation)?;
            if root_item.generation != expected_generation || root_item.flags != 0 {
                return Err(malformed_item(item.key));
            }

            match self.lookup_tree_root(item.key.offset) {
                Ok(_) => {}
                Err(BtrfsError::TreeRootNotFound { .. }) => continue,
                Err(error) => return Err(error),
            }
            let items = self.collect_items_raw(
                TreeRoot {
                    tree_id: TREE_LOG_OBJECT_ID,
                    logical: root_item.logical,
                    level: root_item.level,
                    expected_generation: Some(root_item.generation),
                },
                DiskKey {
                    object_id: 0,
                    item_type: 0,
                    offset: 0,
                },
                DiskKey {
                    object_id: u64::MAX,
                    item_type: u8::MAX,
                    offset: u64::MAX,
                },
            )?;
            overlay.add_tree(
                item.key.offset,
                items,
                sector_size,
                checksum_size,
                super_generation,
            )?;
        }
        overlay.finish()?;
        Ok(overlay)
    }
}

fn parse_range(item: &TreeItem) -> Result<AuthoritativeRange> {
    if !valid_inode_object_id(item.key.object_id) || item.data.len() != size_of::<u64>() {
        return Err(malformed_item(item.key));
    }
    let bytes: [u8; size_of::<u64>()] = item
        .data
        .as_slice()
        .try_into()
        .map_err(|_| malformed_item(item.key))?;
    let end = u64::from_le_bytes(bytes);
    if end < item.key.offset {
        return Err(malformed_item(item.key));
    }
    let item_type = match item.key.item_type {
        DIR_LOG_ITEM_KEY => DIR_ITEM_KEY,
        DIR_LOG_INDEX_KEY => DIR_INDEX_KEY,
        _ => return Err(malformed_item(item.key)),
    };
    Ok(AuthoritativeRange {
        object_id: item.key.object_id,
        item_type,
        start: item.key.offset,
        end,
    })
}

fn normalize_ranges(ranges: &mut Vec<AuthoritativeRange>) {
    ranges.sort_unstable_by_key(|range| (range.object_id, range.item_type, range.start, range.end));
    let mut output: Vec<AuthoritativeRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(previous) = output.last_mut()
            && previous.object_id == range.object_id
            && previous.item_type == range.item_type
            && range.start <= previous.end.saturating_add(1)
        {
            previous.end = previous.end.max(range.end);
        } else {
            output.push(range);
        }
    }
    *ranges = output;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(object_id: u64, item_type: u8, offset: u64, data: &[u8]) -> TreeItem {
        TreeItem {
            key: DiskKey {
                object_id,
                item_type,
                offset,
            },
            data: data.to_vec(),
        }
    }

    #[test]
    fn directory_ranges_replace_committed_items_before_log_insertions() {
        let mut overlay = LogOverlay::default();
        let mut tree = LoggedTree {
            tree_id: 5,
            ..LoggedTree::default()
        };
        tree.authoritative_ranges.push(AuthoritativeRange {
            object_id: 256,
            item_type: DIR_INDEX_KEY,
            start: 3,
            end: 4,
        });
        tree.items.push(item(256, DIR_INDEX_KEY, 8, b"new"));
        overlay.trees.push(tree);

        let committed = alloc::vec![
            item(256, DIR_INDEX_KEY, 2, b"keep"),
            item(256, DIR_INDEX_KEY, 3, b"delete"),
            item(256, DIR_INDEX_KEY, 4, b"rename"),
        ];
        let merged = overlay
            .overlay_items(
                5,
                DiskKey::range_start(256, DIR_INDEX_KEY),
                DiskKey::range_end(256, DIR_INDEX_KEY),
                committed,
            )
            .expect("overlay");
        let offsets: Vec<u64> = merged.iter().map(|item| item.key.offset).collect();
        assert_eq!(offsets, [2, 8]);
    }

    #[test]
    fn adjacent_authoritative_ranges_are_coalesced() {
        let mut ranges = alloc::vec![
            AuthoritativeRange {
                object_id: 256,
                item_type: DIR_INDEX_KEY,
                start: 8,
                end: 10,
            },
            AuthoritativeRange {
                object_id: 256,
                item_type: DIR_INDEX_KEY,
                start: 3,
                end: 7,
            },
        ];
        normalize_ranges(&mut ranges);
        assert_eq!(
            ranges,
            [AuthoritativeRange {
                object_id: 256,
                item_type: DIR_INDEX_KEY,
                start: 3,
                end: 10,
            }]
        );
    }
}
