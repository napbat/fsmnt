//! Logical-to-logical translation through the experimental remap tree.

use fsmnt_parser_core::io::{Read, Seek};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U64, Unaligned};

use super::Btrfs;
use crate::tree::TreeItem;
use crate::{BtrfsError, DiskKey, Result};

pub(super) const REMAP_TREE_OBJECT_ID: u64 = 13;
const IDENTITY_REMAP_KEY: u8 = 234;
const REMAP_KEY: u8 = 235;
const REMAP_BACKREF_KEY: u8 = 236;
const REMAP_ITEM_SIZE: usize = 8;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawRemapItem {
    address: U64<LE>,
}

const _: [(); REMAP_ITEM_SIZE] = [(); core::mem::size_of::<RawRemapItem>()];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RemapTranslation {
    pub(super) logical: u64,
    pub(super) length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemapRange {
    source: u64,
    length: u64,
    target: u64,
}

impl RemapRange {
    fn parse(item: &TreeItem, logical: u64, sector_size: u32) -> Result<Option<Self>> {
        if item.key.item_type == REMAP_BACKREF_KEY
            || !matches!(item.key.item_type, IDENTITY_REMAP_KEY | REMAP_KEY)
        {
            return Ok(None);
        }
        let sector_size = u64::from(sector_size);
        let source = item.key.object_id;
        let length = item.key.offset;
        let end = source
            .checked_add(length)
            .ok_or(BtrfsError::InvalidRemapItem { logical })?;
        if sector_size == 0
            || length == 0
            || !source.is_multiple_of(sector_size)
            || !length.is_multiple_of(sector_size)
            || logical < source
            || logical >= end
        {
            return Err(BtrfsError::InvalidRemapItem { logical });
        }

        let target = match item.key.item_type {
            IDENTITY_REMAP_KEY if item.data.is_empty() => source,
            REMAP_KEY if item.data.len() == REMAP_ITEM_SIZE => {
                let raw = RawRemapItem::ref_from_bytes(&item.data)
                    .map_err(|_| BtrfsError::InvalidRemapItem { logical })?;
                raw.address.get()
            }
            _ => return Err(BtrfsError::InvalidRemapItem { logical }),
        };
        if !target.is_multiple_of(sector_size) || target.checked_add(length).is_none() {
            return Err(BtrfsError::InvalidRemapItem { logical });
        }
        Ok(Some(Self {
            source,
            length,
            target,
        }))
    }

    fn translate(self, logical: u64, requested: usize) -> Result<RemapTranslation> {
        let offset = logical
            .checked_sub(self.source)
            .ok_or(BtrfsError::InvalidRemapItem { logical })?;
        let remaining = self
            .length
            .checked_sub(offset)
            .ok_or(BtrfsError::InvalidRemapItem { logical })?;
        let requested = u64::try_from(requested).map_err(|_| BtrfsError::IntegerOverflow)?;
        let length =
            usize::try_from(remaining.min(requested)).map_err(|_| BtrfsError::IntegerOverflow)?;
        let logical = self
            .target
            .checked_add(offset)
            .ok_or(BtrfsError::InvalidRemapItem { logical })?;
        Ok(RemapTranslation { logical, length })
    }
}

impl<R: Read + Seek> Btrfs<R> {
    pub(super) fn translate_remap(
        &mut self,
        logical: u64,
        requested: usize,
    ) -> Result<RemapTranslation> {
        let root = self
            .remap_root
            .ok_or(BtrfsError::RemapMissing { logical })?;
        let target = DiskKey {
            object_id: logical,
            item_type: u8::MAX,
            offset: u64::MAX,
        };
        let item = self
            .find_predecessor(root, target)?
            .ok_or(BtrfsError::RemapMissing { logical })?;
        let range = RemapRange::parse(&item, logical, self.superblock().sector_size())?
            .ok_or(BtrfsError::RemapMissing { logical })?;
        range.translate(logical, requested)
    }

    pub(super) fn validate_direct_remap_root(&mut self) -> Result<()> {
        let Some(root) = self.remap_root else {
            return Ok(());
        };
        self.read_tree_block(
            root.logical,
            root.level,
            root.tree_id,
            root.expected_generation,
            None,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use zerocopy::IntoBytes;

    use super::{IDENTITY_REMAP_KEY, REMAP_BACKREF_KEY, REMAP_KEY, RawRemapItem, RemapRange};
    use crate::tree::TreeItem;
    use crate::{BtrfsError, DiskKey};

    fn item(item_type: u8, source: u64, length: u64, data: Vec<u8>) -> TreeItem {
        TreeItem {
            key: DiskKey {
                object_id: source,
                item_type,
                offset: length,
            },
            data,
        }
    }

    #[test]
    fn identity_and_forward_items_translate_with_boundary_caps() {
        let identity = item(IDENTITY_REMAP_KEY, 0x10_0000, 0x20_000, Vec::new());
        let range = RemapRange::parse(&identity, 0x11_0000, 4096)
            .expect("identity parse")
            .expect("identity range");
        assert_eq!(
            range.translate(0x11_0000, 0x20_000).expect("identity"),
            super::RemapTranslation {
                logical: 0x11_0000,
                length: 0x10_000,
            }
        );

        let forward = item(
            REMAP_KEY,
            0x20_0000,
            0x20_000,
            RawRemapItem {
                address: zerocopy::U64::new(0x50_0000),
            }
            .as_bytes()
            .to_vec(),
        );
        let range = RemapRange::parse(&forward, 0x21_0000, 4096)
            .expect("remap parse")
            .expect("remap range");
        assert_eq!(
            range.translate(0x21_0000, 4096).expect("remap"),
            super::RemapTranslation {
                logical: 0x51_0000,
                length: 4096,
            }
        );
    }

    #[test]
    fn backrefs_are_not_forward_translations() {
        let backref = item(REMAP_BACKREF_KEY, 0x10_0000, 4096, Vec::new());
        assert_eq!(
            RemapRange::parse(&backref, 0x10_0000, 4096).expect("backref"),
            None
        );
    }

    #[test]
    fn malformed_ranges_and_payloads_fail_closed() {
        let misaligned = item(IDENTITY_REMAP_KEY, 1, 4096, Vec::new());
        assert!(matches!(
            RemapRange::parse(&misaligned, 1, 4096),
            Err(BtrfsError::InvalidRemapItem { .. })
        ));
        let payload = item(REMAP_KEY, 0x10_0000, 4096, vec![0_u8; 7]);
        assert!(matches!(
            RemapRange::parse(&payload, 0x10_0000, 4096),
            Err(BtrfsError::InvalidRemapItem { .. })
        ));
    }
}
