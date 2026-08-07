//! Extent-tree-v2 global roots and block-group-to-root selection.

use alloc::vec::Vec;

use fsmnt_parser_core::io::{Read, Seek};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U32, U64, Unaligned,
};

use super::Btrfs;
use crate::item::{ROOT_ITEM_KEY, ROOT_TREE_OBJECT_ID, RootItem};
use crate::superblock::{EXTENT_TREE_V2_INCOMPAT, REMAP_TREE_INCOMPAT};
use crate::tree::{TreeItem, TreeRoot};
use crate::{BtrfsError, DiskKey, Result};

const EXTENT_TREE_OBJECT_ID: u64 = 2;
const FREE_SPACE_TREE_OBJECT_ID: u64 = 10;
const BLOCK_GROUP_TREE_OBJECT_ID: u64 = 11;
const FIRST_CHUNK_TREE_OBJECT_ID: u64 = 256;
const BLOCK_GROUP_ITEM_KEY: u8 = 192;
const BLOCK_GROUP_PROFILE_MASK: u64 = ((1_u64 << 11) - 1) & !0b111;
const SUPPORTED_BLOCK_GROUP_FLAGS: u64 = (1_u64 << 13) - 1;
const BLOCK_GROUP_ITEM_SIZE: usize = 24;
const BLOCK_GROUP_ITEM_V2_SIZE: usize = 36;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawBlockGroupItem {
    used: U64<LE>,
    chunk_objectid: U64<LE>,
    flags: U64<LE>,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawBlockGroupItemV2 {
    common: RawBlockGroupItem,
    remap_bytes: U64<LE>,
    identity_remap_count: U32<LE>,
}

const _: [(); BLOCK_GROUP_ITEM_SIZE] = [(); core::mem::size_of::<RawBlockGroupItem>()];
const _: [(); BLOCK_GROUP_ITEM_V2_SIZE] = [(); core::mem::size_of::<RawBlockGroupItemV2>()];

#[derive(Clone, Copy)]
pub(super) struct CachedRoot {
    pub(super) key_offset: u64,
    pub(super) root: TreeRoot,
}

impl CachedRoot {
    pub(super) const fn new(key_offset: u64, root: TreeRoot) -> Self {
        Self { key_offset, root }
    }
}

#[derive(Clone, Copy)]
struct ChunkSpec {
    logical: u64,
    length: u64,
    flags: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockGroupAssignment {
    logical: u64,
    length: u64,
    global_root_id: u64,
}

impl BlockGroupAssignment {
    fn parse(
        item: &TreeItem,
        chunk: ChunkSpec,
        extent_tree_v2: bool,
        global_root_count: u64,
        remap_tree: bool,
        sector_size: u32,
    ) -> Result<Self> {
        let valid_key = item.key.object_id == chunk.logical
            && item.key.item_type == BLOCK_GROUP_ITEM_KEY
            && item.key.offset == chunk.length;
        let expected_size = if remap_tree {
            BLOCK_GROUP_ITEM_V2_SIZE
        } else {
            BLOCK_GROUP_ITEM_SIZE
        };
        if !valid_key || item.data.len() != expected_size {
            return Err(BtrfsError::InvalidBlockGroupItem {
                logical: chunk.logical,
            });
        }
        let raw = RawBlockGroupItem::ref_from_prefix(&item.data)
            .map(|(raw, _)| raw)
            .map_err(|_| BtrfsError::InvalidBlockGroupItem {
                logical: chunk.logical,
            })?;
        let flags = raw.flags.get();
        let profile = flags & BLOCK_GROUP_PROFILE_MASK;
        let valid = chunk.length != 0
            && raw.used.get() <= chunk.length
            && flags & !SUPPORTED_BLOCK_GROUP_FLAGS == 0
            && profile.count_ones() <= 1
            && flags == chunk.flags;
        if !valid {
            return Err(BtrfsError::InvalidBlockGroupItem {
                logical: chunk.logical,
            });
        }
        if remap_tree {
            let raw_v2 = RawBlockGroupItemV2::ref_from_bytes(&item.data).map_err(|_| {
                BtrfsError::InvalidBlockGroupItem {
                    logical: chunk.logical,
                }
            })?;
            let maximum_identity_items = chunk.length / u64::from(sector_size);
            if raw_v2.remap_bytes.get() > chunk.length
                || u64::from(raw_v2.identity_remap_count.get()) > maximum_identity_items
            {
                return Err(BtrfsError::InvalidBlockGroupItem {
                    logical: chunk.logical,
                });
            }
        }
        let chunk_objectid = raw.chunk_objectid.get();
        let global_root_id = if extent_tree_v2 {
            if chunk_objectid >= global_root_count {
                return Err(BtrfsError::InvalidBlockGroupRootId {
                    logical: chunk.logical,
                    global_root_id: chunk_objectid,
                    global_root_count,
                });
            }
            chunk_objectid
        } else {
            if chunk_objectid != FIRST_CHUNK_TREE_OBJECT_ID {
                return Err(BtrfsError::InvalidBlockGroupItem {
                    logical: chunk.logical,
                });
            }
            0
        };
        Ok(Self {
            logical: chunk.logical,
            length: chunk.length,
            global_root_id,
        })
    }

    fn contains(self, logical: u64) -> bool {
        logical >= self.logical && logical < self.logical.saturating_add(self.length)
    }

    fn remaining(self, logical: u64) -> Result<u64> {
        self.logical
            .checked_add(self.length)
            .and_then(|end| end.checked_sub(logical))
            .ok_or(BtrfsError::IntegerOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ChecksumScope {
    pub(super) global_root_id: u64,
    pub(super) remaining: u64,
}

#[derive(Default)]
pub(super) struct GlobalRootState {
    extent_tree_v2: bool,
    block_groups: Vec<BlockGroupAssignment>,
}

impl GlobalRootState {
    pub(super) fn checksum_scope(&self, logical: u64) -> Result<ChecksumScope> {
        if !self.extent_tree_v2 {
            return Ok(ChecksumScope {
                global_root_id: 0,
                remaining: u64::MAX,
            });
        }
        let assignment = self
            .block_groups
            .iter()
            .copied()
            .find(|assignment| assignment.contains(logical))
            .ok_or(BtrfsError::InvalidBlockGroupItem { logical })?;
        Ok(ChecksumScope {
            global_root_id: assignment.global_root_id,
            remaining: assignment.remaining(logical)?,
        })
    }
}

impl<R: Read + Seek> Btrfs<R> {
    pub(super) fn load_global_root_state(&mut self) -> Result<GlobalRootState> {
        let incompat_flags = self.superblock().incompat_flags();
        let extent_tree_v2 = incompat_flags & EXTENT_TREE_V2_INCOMPAT != 0;
        let remap_tree = incompat_flags & REMAP_TREE_INCOMPAT != 0;
        if !extent_tree_v2 && !remap_tree {
            return Ok(GlobalRootState::default());
        }

        let global_root_count = if extent_tree_v2 {
            self.superblock().global_root_count()
        } else {
            1
        };
        let sector_size = self.superblock().sector_size();
        if extent_tree_v2 {
            for tree_id in [
                EXTENT_TREE_OBJECT_ID,
                crate::item::CHECKSUM_TREE_OBJECT_ID,
                FREE_SPACE_TREE_OBJECT_ID,
            ] {
                self.cache_global_root_set(tree_id, global_root_count)?;
            }
        }

        let block_group_root = self.lookup_tree_root(BLOCK_GROUP_TREE_OBJECT_ID)?;
        let chunks: Vec<ChunkSpec> = self
            .chunks
            .iter()
            .map(|chunk| ChunkSpec {
                logical: chunk.logical,
                length: chunk.length,
                flags: chunk.flags,
            })
            .collect();
        let mut block_groups = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let key = DiskKey {
                object_id: chunk.logical,
                item_type: BLOCK_GROUP_ITEM_KEY,
                offset: chunk.length,
            };
            let items = self.collect_items_raw(block_group_root, key, key)?;
            let [item] = items.as_slice() else {
                return Err(BtrfsError::InvalidBlockGroupItem {
                    logical: chunk.logical,
                });
            };
            block_groups.push(BlockGroupAssignment::parse(
                item,
                chunk,
                extent_tree_v2,
                global_root_count,
                remap_tree,
                sector_size,
            )?);
        }

        Ok(GlobalRootState {
            extent_tree_v2,
            block_groups,
        })
    }

    fn cache_global_root_set(&mut self, tree_id: u64, expected_count: u64) -> Result<()> {
        let root_tree = self.root_tree.ok_or(BtrfsError::TreeRootNotFound {
            tree_id: ROOT_TREE_OBJECT_ID,
        })?;
        let items = self.collect_items_raw(
            root_tree,
            DiskKey::range_start(tree_id, ROOT_ITEM_KEY),
            DiskKey::range_end(tree_id, ROOT_ITEM_KEY),
        )?;
        let actual_count = u64::try_from(items.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
        if actual_count != expected_count {
            return Err(BtrfsError::GlobalRootCountMismatch {
                tree_id,
                expected: expected_count,
                actual: actual_count,
            });
        }

        let sector_size = self.superblock().sector_size();
        let super_generation = self.active_generation();
        for (index, item) in items.into_iter().enumerate() {
            let expected = u64::try_from(index).map_err(|_| BtrfsError::IntegerOverflow)?;
            if item.key.offset != expected {
                return Err(BtrfsError::InvalidGlobalRootId {
                    tree_id,
                    expected,
                    actual: item.key.offset,
                });
            }
            let root_item = RootItem::parse(item.key, &item.data, sector_size, super_generation)?;
            self.cached_roots.push(CachedRoot::new(
                root_item.key_offset,
                TreeRoot {
                    tree_id,
                    logical: root_item.logical,
                    level: root_item.level,
                    expected_generation: Some(root_item.generation),
                },
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use zerocopy::{FromBytes, IntoBytes, U32, U64};

    use super::{
        BLOCK_GROUP_ITEM_KEY, BlockGroupAssignment, ChunkSpec, FIRST_CHUNK_TREE_OBJECT_ID,
        GlobalRootState, RawBlockGroupItem, RawBlockGroupItemV2,
    };
    use crate::{BtrfsError, DiskKey};

    fn item(chunk_objectid: u64, used: u64, flags: u64) -> crate::tree::TreeItem {
        crate::tree::TreeItem {
            key: DiskKey {
                object_id: 0x10_0000,
                item_type: BLOCK_GROUP_ITEM_KEY,
                offset: 0x20_0000,
            },
            data: RawBlockGroupItem {
                used: U64::new(used),
                chunk_objectid: U64::new(chunk_objectid),
                flags: U64::new(flags),
            }
            .as_bytes()
            .to_vec(),
        }
    }

    fn chunk() -> ChunkSpec {
        ChunkSpec {
            logical: 0x10_0000,
            length: 0x20_0000,
            flags: 1,
        }
    }

    #[test]
    fn typed_block_group_selects_global_root() {
        let assignment =
            BlockGroupAssignment::parse(&item(3, 4096, 1), chunk(), true, 4, false, 4096)
                .expect("block group");
        assert_eq!(assignment.global_root_id, 3);
        assert_eq!(
            assignment.remaining(0x11_0000).expect("remaining"),
            0x1f_0000
        );
    }

    #[test]
    fn block_group_rejects_invalid_geometry_and_root_id() {
        assert!(matches!(
            BlockGroupAssignment::parse(&item(4, 4096, 1), chunk(), true, 4, false, 4096),
            Err(BtrfsError::InvalidBlockGroupRootId { .. })
        ));
        assert!(matches!(
            BlockGroupAssignment::parse(&item(0, 0x20_0001, 1), chunk(), true, 4, false, 4096),
            Err(BtrfsError::InvalidBlockGroupItem { .. })
        ));
        assert!(matches!(
            BlockGroupAssignment::parse(&item(0, 4096, 2), chunk(), true, 4, false, 4096),
            Err(BtrfsError::InvalidBlockGroupItem { .. })
        ));
    }

    #[test]
    fn remap_tree_requires_and_validates_v2_block_group_items() {
        let chunk = chunk();
        let item = crate::tree::TreeItem {
            key: DiskKey {
                object_id: chunk.logical,
                item_type: BLOCK_GROUP_ITEM_KEY,
                offset: chunk.length,
            },
            data: RawBlockGroupItemV2 {
                common: RawBlockGroupItem {
                    used: U64::new(4096),
                    chunk_objectid: U64::new(0),
                    flags: U64::new(chunk.flags),
                },
                remap_bytes: U64::new(4096),
                identity_remap_count: U32::new(1),
            }
            .as_bytes()
            .to_vec(),
        };
        BlockGroupAssignment::parse(&item, chunk, true, 1, true, 4096)
            .expect("valid v2 block group");
        assert!(matches!(
            BlockGroupAssignment::parse(&item, chunk, true, 1, false, 4096),
            Err(BtrfsError::InvalidBlockGroupItem { .. })
        ));
    }

    #[test]
    fn remap_tree_without_extent_tree_v2_uses_chunk_objectid() {
        let chunk = chunk();
        let item = crate::tree::TreeItem {
            key: DiskKey {
                object_id: chunk.logical,
                item_type: BLOCK_GROUP_ITEM_KEY,
                offset: chunk.length,
            },
            data: RawBlockGroupItemV2 {
                common: RawBlockGroupItem {
                    used: U64::new(4096),
                    chunk_objectid: U64::new(FIRST_CHUNK_TREE_OBJECT_ID),
                    flags: U64::new(chunk.flags),
                },
                remap_bytes: U64::new(0),
                identity_remap_count: U32::new(0),
            }
            .as_bytes()
            .to_vec(),
        };
        let assignment = BlockGroupAssignment::parse(&item, chunk, false, 1, true, 4096)
            .expect("ordinary chunk object ID in v2 item");
        assert_eq!(assignment.global_root_id, 0);

        let mut invalid = item;
        RawBlockGroupItemV2::mut_from_bytes(&mut invalid.data)
            .expect("typed v2 item")
            .common
            .chunk_objectid = U64::new(0);
        assert!(matches!(
            BlockGroupAssignment::parse(&invalid, chunk, false, 1, true, 4096),
            Err(BtrfsError::InvalidBlockGroupItem { .. })
        ));
    }

    #[test]
    fn checksum_scope_stops_at_block_group_boundary() {
        let state = GlobalRootState {
            extent_tree_v2: true,
            block_groups: vec![BlockGroupAssignment {
                logical: 0x10_0000,
                length: 0x20_0000,
                global_root_id: 2,
            }],
        };
        let scope = state.checksum_scope(0x2f_0000).expect("checksum scope");
        assert_eq!(scope.global_root_id, 2);
        assert_eq!(scope.remaining, 0x1_0000);
    }
}
