//! Uniform direct/indirect block-tree descriptors.

use crate::superblock::{ByteOrder, QNX6_MAX_LEVELS};
use crate::{Qnx6Error, Result};

/// The fields shared by metadata roots and inode data trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeDescriptor {
    size: u64,
    pointers: [u32; 16],
    levels: u8,
}

impl TreeDescriptor {
    pub(crate) fn parse(
        bytes: &[u8],
        size_offset: usize,
        pointers_offset: usize,
        levels_offset: usize,
        order: ByteOrder,
        tree: &'static str,
    ) -> Result<Self> {
        let mut pointers = [0_u32; 16];
        for (index, pointer) in pointers.iter_mut().enumerate() {
            *pointer = order.read_u32(bytes, pointers_offset + index * 4);
        }
        let levels = bytes[levels_offset];
        if levels > QNX6_MAX_LEVELS {
            return Err(Qnx6Error::InvalidTreeDepth { tree, levels });
        }
        Ok(Self {
            size: order.read_u64(bytes, size_offset),
            pointers,
            levels,
        })
    }

    pub(crate) const fn size(&self) -> u64 {
        self.size
    }

    pub(crate) const fn pointers(&self) -> &[u32; 16] {
        &self.pointers
    }

    pub(crate) const fn levels(&self) -> u8 {
        self.levels
    }
}
