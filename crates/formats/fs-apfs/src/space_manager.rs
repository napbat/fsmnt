//! The space manager (`spaceman_phys_t`) — free-space and allocation
//! mapping.
//!
//! The space manager tracks which blocks of a container are allocated. Its
//! per-chunk allocation bitmaps are the basis for free-space reporting and
//! for unallocated-block recovery scanning.
//!
//! Apple File System Reference, `16-space-manager.md`.

use alloc::vec::Vec;

use zerocopy::{FromBytes, I64, Immutable, KnownLayout, LittleEndian as LE, U32, U64, Unaligned};

use crate::checkpoint::read_block;
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::object::OBJ_PHYS_SIZE;

/// Number of storage devices a space manager describes (`SD_COUNT`).
pub const SD_COUNT: usize = 2;
/// Index of the main storage device (`SD_MAIN`).
pub const SD_MAIN: usize = 0;
/// Offset of the `sm_dev` array within `spaceman_phys_t`.
const SM_DEV_OFFSET: usize = OBJ_PHYS_SIZE + 16;
/// Size of a `spaceman_device_t`.
const SPACEMAN_DEVICE_SIZE: usize = 48;
/// Size of a `chunk_info_t`.
const CHUNK_INFO_SIZE: usize = 32;
/// Offset of the `chunk_info` array within a `chunk_info_block`.
const CIB_CHUNK_INFO_OFFSET: usize = OBJ_PHYS_SIZE + 8;
/// Offset of the `cab_cib_addr` array within a `cib_addr_block` (after the
/// object header, `cab_index`, and `cab_cib_count`).
const CAB_CIB_ADDR_OFFSET: usize = OBJ_PHYS_SIZE + 8;
/// Offset of `cab_cib_count` within a `cib_addr_block`.
const CAB_CIB_COUNT_OFFSET: usize = OBJ_PHYS_SIZE + 4;

/// On-disk `spaceman_device_t` (48 bytes).
#[allow(
    clippy::struct_field_names,
    reason = "the sm_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawSpacemanDevice {
    sm_block_count: U64<LE>,
    sm_chunk_count: U64<LE>,
    sm_cib_count: U32<LE>,
    sm_cab_count: U32<LE>,
    sm_free_count: U64<LE>,
    sm_addr_offset: U32<LE>,
    sm_reserved: U32<LE>,
    sm_reserved2: U64<LE>,
}

/// On-disk `chunk_info_t` (32 bytes).
#[allow(
    clippy::struct_field_names,
    reason = "the ci_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawChunkInfo {
    ci_xid: U64<LE>,
    ci_addr: U64<LE>,
    ci_block_count: U32<LE>,
    ci_free_count: U32<LE>,
    ci_bitmap_addr: I64<LE>,
}

/// One of a space manager's storage devices (`spaceman_device_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpacemanDevice {
    /// Total number of blocks on the device.
    pub block_count: u64,
    /// Number of allocation chunks on the device.
    pub chunk_count: u64,
    /// Number of chunk-info blocks.
    pub cib_count: u32,
    /// Number of chunk-info address blocks (zero for a single-level layout).
    pub cab_count: u32,
    /// Number of free blocks on the device.
    pub free_count: u64,
    /// Offset, within `spaceman_phys_t`, of the device's address array.
    addr_offset: u32,
}

/// A parsed space manager.
#[derive(Debug, Clone)]
pub struct SpaceManager {
    /// The space-manager block, kept to read the per-device address arrays.
    block: Vec<u8>,
    /// Container block size, in bytes.
    pub block_size: u32,
    /// Number of blocks per allocation chunk.
    pub blocks_per_chunk: u32,
    /// Number of chunks per chunk-info block.
    pub chunks_per_cib: u32,
    /// Number of chunk-info blocks per chunk-info address block (the
    /// two-level layout).
    pub cibs_per_cab: u32,
    /// The main storage device.
    pub main_device: SpacemanDevice,
    /// The secondary (Fusion tier-2) storage device.
    pub tier2_device: SpacemanDevice,
}

/// Parses a `spaceman_device_t` at `offset` within `block`.
fn parse_device(block: &[u8], offset: usize) -> Result<SpacemanDevice> {
    let raw = block
        .get(offset..offset + SPACEMAN_DEVICE_SIZE)
        .and_then(|slice| RawSpacemanDevice::ref_from_bytes(slice).ok())
        .ok_or(ApfsError::Truncated {
            structure: "spaceman_device_t",
            expected: offset + SPACEMAN_DEVICE_SIZE,
            actual: block.len(),
        })?;
    Ok(SpacemanDevice {
        block_count: raw.sm_block_count.get(),
        chunk_count: raw.sm_chunk_count.get(),
        cib_count: raw.sm_cib_count.get(),
        cab_count: raw.sm_cab_count.get(),
        free_count: raw.sm_free_count.get(),
        addr_offset: raw.sm_addr_offset.get(),
    })
}

impl SpaceManager {
    /// Parses a space manager from its (ephemeral) block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a block too small to hold the
    /// fixed `spaceman_phys_t` fields.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed-width space-manager field ceases to fit the
    /// minimum block length checked before parsing.
    pub fn parse(block: Vec<u8>) -> Result<Self> {
        if block.len() < SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE {
            return Err(ApfsError::Truncated {
                structure: "spaceman_phys_t",
                expected: SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE,
                actual: block.len(),
            });
        }
        let block_size = u32::from_le_bytes(block[0x20..0x24].try_into().expect("4 bytes"));
        let blocks_per_chunk = u32::from_le_bytes(block[0x24..0x28].try_into().expect("4 bytes"));
        let chunks_per_cib = u32::from_le_bytes(block[0x28..0x2C].try_into().expect("4 bytes"));
        let cibs_per_cab = u32::from_le_bytes(block[0x2C..0x30].try_into().expect("4 bytes"));
        let main_device = parse_device(&block, SM_DEV_OFFSET)?;
        let tier2_device = parse_device(&block, SM_DEV_OFFSET + SPACEMAN_DEVICE_SIZE)?;
        Ok(Self {
            block,
            block_size,
            blocks_per_chunk,
            chunks_per_cib,
            cibs_per_cab,
            main_device,
            tier2_device,
        })
    }

    /// Total number of blocks tracked across both devices.
    #[must_use]
    pub fn total_blocks(&self) -> u64 {
        self.main_device.block_count + self.tier2_device.block_count
    }

    /// Number of free blocks across both devices.
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        self.main_device.free_count + self.tier2_device.free_count
    }

    /// Reads the `index`-th eight-byte address from the main device's
    /// address array in the space-manager block.
    fn device_address(&self, index: u64) -> Result<u64> {
        let entry = self.main_device.addr_offset as usize
            + usize::try_from(index)
                .unwrap_or(usize::MAX)
                .saturating_mul(8);
        let addr = self
            .block
            .get(entry..entry + 8)
            .ok_or(ApfsError::Malformed {
                structure: "spaceman_phys_t",
                reason: "device address array out of range",
            })?;
        Ok(u64::from_le_bytes(addr.try_into().expect("8 bytes")))
    }

    /// Resolves the chunk-info-block address for `chunk_index` on the main
    /// device.
    ///
    /// A single-level device (`cab_count == 0`) indexes the chunk-info
    /// blocks directly; a two-level device walks a chunk-info address block
    /// (`cib_addr_block`) — Apple File System Reference, `16-space-manager.md`.
    fn cib_address<T: Read + Seek>(&self, reader: &mut T, chunk_index: u64) -> Result<u64> {
        let chunks_per_cib = u64::from(self.chunks_per_cib);
        if chunks_per_cib == 0 {
            return Err(ApfsError::Malformed {
                structure: "spaceman_phys_t",
                reason: "chunks-per-cib is zero",
            });
        }
        let cib_index = chunk_index / chunks_per_cib;
        if cib_index >= u64::from(self.main_device.cib_count) {
            return Err(ApfsError::Malformed {
                structure: "spaceman_device_t",
                reason: "chunk index past the device's chunk-info blocks",
            });
        }
        if self.main_device.cab_count == 0 {
            // Single-level: the address array holds CIB addresses directly.
            return self.device_address(cib_index);
        }
        // Two-level: the address array holds CAB addresses; each CAB lists
        // the addresses of `cibs_per_cab` chunk-info blocks.
        let cibs_per_cab = u64::from(self.cibs_per_cab);
        if cibs_per_cab == 0 {
            return Err(ApfsError::Malformed {
                structure: "spaceman_phys_t",
                reason: "cibs-per-cab is zero with a two-level layout",
            });
        }
        let address_block_index = cib_index / cibs_per_cab;
        let cib_in_cab = cib_index % cibs_per_cab;
        if address_block_index >= u64::from(self.main_device.cab_count) {
            return Err(ApfsError::Malformed {
                structure: "spaceman_device_t",
                reason: "chunk index past the device's address blocks",
            });
        }
        let cab = read_block(
            reader,
            self.block_size,
            self.device_address(address_block_index)?,
        )?;
        let cab_cib_count = u64::from(u32::from_le_bytes(
            cab.get(CAB_CIB_COUNT_OFFSET..CAB_CIB_COUNT_OFFSET + 4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ApfsError::Malformed {
                    structure: "cib_addr_block",
                    reason: "truncated address block",
                })?,
        ));
        if cib_in_cab >= cab_cib_count {
            return Err(ApfsError::Malformed {
                structure: "cib_addr_block",
                reason: "chunk-info-block index past the address block",
            });
        }
        let entry = CAB_CIB_ADDR_OFFSET + usize::try_from(cib_in_cab).unwrap_or(usize::MAX) * 8;
        let addr = cab.get(entry..entry + 8).ok_or(ApfsError::Malformed {
            structure: "cib_addr_block",
            reason: "chunk-info-block address out of range",
        })?;
        Ok(u64::from_le_bytes(addr.try_into().expect("8 bytes")))
    }

    /// Reads the `chunk_info_t` for `chunk_index` on the main device.
    fn chunk_info<T: Read + Seek>(&self, reader: &mut T, chunk_index: u64) -> Result<RawChunkInfo> {
        let cib_addr = self.cib_address(reader, chunk_index)?;
        let chunk_in_cib =
            usize::try_from(chunk_index % u64::from(self.chunks_per_cib)).unwrap_or(usize::MAX);
        let cib = read_block(reader, self.block_size, cib_addr)?;
        let ci_start = CIB_CHUNK_INFO_OFFSET + chunk_in_cib * CHUNK_INFO_SIZE;
        cib.get(ci_start..ci_start + CHUNK_INFO_SIZE)
            .and_then(|slice| RawChunkInfo::ref_from_bytes(slice).ok())
            .copied()
            .ok_or(ApfsError::Malformed {
                structure: "chunk_info_block",
                reason: "chunk-info entry out of range",
            })
    }

    /// Returns whether the block at `block_addr` on the **main device** is
    /// allocated.
    ///
    /// Tier-2 (Fusion hard-drive) allocation is not queried here; a
    /// `block_addr` past the main device is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Malformed`] for an out-of-range address or a
    /// malformed space manager, and propagates I/O errors.
    pub fn is_allocated<T: Read + Seek>(&self, reader: &mut T, block_addr: u64) -> Result<bool> {
        if block_addr >= self.main_device.block_count {
            return Err(ApfsError::Malformed {
                structure: "spaceman",
                reason: "block address past the main device",
            });
        }
        let blocks_per_chunk = u64::from(self.blocks_per_chunk);
        if blocks_per_chunk == 0 {
            return Err(ApfsError::Malformed {
                structure: "spaceman_phys_t",
                reason: "blocks-per-chunk is zero",
            });
        }
        let chunk_index = block_addr / blocks_per_chunk;
        let info = self.chunk_info(reader, chunk_index)?;
        let bitmap_addr = info.ci_bitmap_addr.get();

        // A chunk with no bitmap is uniformly allocated or uniformly free.
        if bitmap_addr <= 0 {
            return Ok(info.ci_free_count.get() == 0 && info.ci_block_count.get() != 0);
        }
        let bitmap_addr = u64::try_from(bitmap_addr).map_err(|_| ApfsError::Malformed {
            structure: "chunk_info_t",
            reason: "bitmap address is negative",
        })?;
        let bitmap = read_block(reader, self.block_size, bitmap_addr)?;
        let bit = usize::try_from(block_addr % blocks_per_chunk).unwrap_or(usize::MAX);
        let byte = bitmap.get(bit / 8).ok_or(ApfsError::Malformed {
            structure: "spaceman bitmap",
            reason: "bit index past the bitmap block",
        })?;
        // A set bit marks an allocated block.
        Ok(byte & (1 << (bit % 8)) != 0)
    }

    /// Lists every free (unallocated) extent on the main device.
    ///
    /// The chunks are scanned in order, and contiguous free blocks — across
    /// chunk boundaries — are coalesced into a single [`FreeExtent`], so the
    /// extents are non-overlapping and their lengths sum to the device's
    /// free-block count. This lets a recovery scan iterate only the
    /// unallocated ranges instead of probing every block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Malformed`] for a malformed space manager, and
    /// propagates I/O errors.
    pub fn free_extents<T: Read + Seek>(&self, reader: &mut T) -> Result<Vec<FreeExtent>> {
        let blocks_per_chunk = u64::from(self.blocks_per_chunk);
        if blocks_per_chunk == 0 {
            return Err(ApfsError::Malformed {
                structure: "spaceman_phys_t",
                reason: "blocks-per-chunk is zero",
            });
        }
        let mut extents: Vec<FreeExtent> = Vec::new();
        for chunk_index in 0..self.main_device.chunk_count {
            let chunk_start = chunk_index.saturating_mul(blocks_per_chunk);
            let info = self.chunk_info(reader, chunk_index)?;
            let block_count = u64::from(info.ci_block_count.get());
            let bitmap_addr = info.ci_bitmap_addr.get();
            if bitmap_addr <= 0 {
                // Uniform chunk: every block free, or every block allocated.
                if info.ci_free_count.get() != 0 {
                    push_free(&mut extents, chunk_start, block_count);
                }
                continue;
            }
            let bitmap_addr = u64::try_from(bitmap_addr).map_err(|_| ApfsError::Malformed {
                structure: "chunk_info_t",
                reason: "bitmap address is negative",
            })?;
            let bitmap = read_block(reader, self.block_size, bitmap_addr)?;
            // The bitmap block must cover every block of the chunk.
            if (bitmap.len() as u64).saturating_mul(8) < block_count {
                return Err(ApfsError::Malformed {
                    structure: "spaceman bitmap",
                    reason: "bitmap is shorter than the chunk it covers",
                });
            }
            let mut run_start: Option<u64> = None;
            for bit in 0..block_count {
                let idx = usize::try_from(bit).unwrap_or(usize::MAX);
                let allocated = bitmap[idx / 8] & (1 << (idx % 8)) != 0;
                if allocated {
                    if let Some(start) = run_start.take() {
                        push_free(&mut extents, chunk_start + start, bit - start);
                    }
                } else if run_start.is_none() {
                    run_start = Some(bit);
                }
            }
            if let Some(start) = run_start {
                push_free(&mut extents, chunk_start + start, block_count - start);
            }
        }
        Ok(extents)
    }
}

/// A run of contiguous free (unallocated) blocks on the main device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeExtent {
    /// First free block of the run.
    pub start: u64,
    /// Number of consecutive free blocks.
    pub length: u64,
}

/// Appends a free run, coalescing it with the previous extent when the two
/// are contiguous.
fn push_free(extents: &mut Vec<FreeExtent>, start: u64, length: u64) {
    if length == 0 {
        return;
    }
    if let Some(last) = extents.last_mut()
        && last.start.saturating_add(last.length) == start
    {
        last.length += length;
        return;
    }
    extents.push(FreeExtent { start, length });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const BLK: usize = 4096;

    /// Builds a `spaceman_phys_t` block. The main device has `cib_count`
    /// chunk-info blocks whose addresses follow the fixed fields.
    fn spaceman(
        blocks_per_chunk: u32,
        chunks_per_cib: u32,
        main_blocks: u64,
        main_free: u64,
        cib_count: u32,
        cib_addrs: &[u64],
    ) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x24].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x24..0x28].copy_from_slice(&blocks_per_chunk.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&chunks_per_cib.to_le_bytes());
        // sm_dev[SD_MAIN].
        let dev = SM_DEV_OFFSET;
        b[dev..dev + 8].copy_from_slice(&main_blocks.to_le_bytes());
        let chunk_count = if blocks_per_chunk > 0 {
            main_blocks.div_ceil(u64::from(blocks_per_chunk))
        } else {
            0
        };
        b[dev + 8..dev + 16].copy_from_slice(&chunk_count.to_le_bytes());
        b[dev + 16..dev + 20].copy_from_slice(&cib_count.to_le_bytes());
        b[dev + 24..dev + 32].copy_from_slice(&main_free.to_le_bytes());
        // The CIB address array sits after both spaceman_device_t structs.
        let addr_off = SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE;
        b[dev + 32..dev + 36].copy_from_slice(
            &u32::try_from(addr_off)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        for (i, &addr) in cib_addrs.iter().enumerate() {
            b[addr_off + i * 8..addr_off + i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
        b
    }

    /// Builds a chunk-info block with one chunk whose bitmap is at `bitmap`.
    fn cib(chunk_blocks: u32, free_count: u32, bitmap: i64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&1u32.to_le_bytes()); // count
        let ci = CIB_CHUNK_INFO_OFFSET;
        b[ci + 16..ci + 20].copy_from_slice(&chunk_blocks.to_le_bytes());
        b[ci + 20..ci + 24].copy_from_slice(&free_count.to_le_bytes());
        b[ci + 24..ci + 32].copy_from_slice(&bitmap.to_le_bytes());
        b
    }

    #[test]
    fn parses_geometry_and_counts() {
        let sm = SpaceManager::parse(spaceman(8, 100, 5000, 1200, 1, &[3])).unwrap();
        assert_eq!(
            sm.block_size,
            u32::try_from(BLK).expect("the test fixture value fits in u32")
        );
        assert_eq!(sm.blocks_per_chunk, 8);
        assert_eq!(sm.total_blocks(), 5000);
        assert_eq!(sm.free_blocks(), 1200);
    }

    #[test]
    fn parse_rejects_a_short_block() {
        assert!(matches!(
            SpaceManager::parse(vec![0u8; 64]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn is_allocated_reads_the_chunk_bitmap() {
        // One chunk of 32 blocks; CIB at block 1, bitmap at block 2.
        // Bitmap: block 0 and block 5 allocated, the rest free.
        let mut bitmap = vec![0u8; BLK];
        bitmap[0] = 0b0010_0001; // bits 0 and 5 set
        let image: Vec<u8> = {
            let mut data = spaceman(32, 100, 32, 30, 1, &[1]);
            data.extend(cib(32, 30, 2)); // block 1
            data.extend(bitmap); // block 2
            data
        };
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        assert!(sm.is_allocated(&mut reader, 0).unwrap());
        assert!(!sm.is_allocated(&mut reader, 1).unwrap());
        assert!(sm.is_allocated(&mut reader, 5).unwrap());
        assert!(!sm.is_allocated(&mut reader, 31).unwrap());
    }

    #[test]
    fn is_allocated_handles_a_bitmapless_full_chunk() {
        // ci_bitmap_addr 0 with free_count 0 -> the whole chunk is allocated.
        let image: Vec<u8> = {
            let mut data = spaceman(32, 100, 32, 0, 1, &[1]);
            data.extend(cib(32, 0, 0)); // block 1, no bitmap
            data
        };
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        assert!(sm.is_allocated(&mut reader, 10).unwrap());
    }

    #[test]
    fn is_allocated_rejects_an_out_of_range_block() {
        let sm = SpaceManager::parse(spaceman(8, 100, 100, 0, 1, &[1])).unwrap();
        let mut reader = Cursor::new(vec![0u8; BLK]);
        assert!(matches!(
            sm.is_allocated(&mut reader, 500),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn zero_chunks_per_cib_is_an_error_not_a_panic() {
        // A spaceman with chunks_per_cib == 0 must yield an ApfsError rather
        // than panicking on the chunk-in-cib modulo.
        let sm = SpaceManager::parse(spaceman(8, 0, 100, 0, 1, &[1])).unwrap();
        let mut reader = Cursor::new(vec![0u8; BLK]);
        assert!(matches!(
            sm.is_allocated(&mut reader, 0),
            Err(ApfsError::Malformed { .. })
        ));
    }

    /// Builds a `cib_addr_block` listing the given chunk-info-block
    /// addresses.
    fn cab(cib_addrs: &[u64]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[CAB_CIB_COUNT_OFFSET..CAB_CIB_COUNT_OFFSET + 4].copy_from_slice(
            &u32::try_from(cib_addrs.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        for (i, &addr) in cib_addrs.iter().enumerate() {
            let off = CAB_CIB_ADDR_OFFSET + i * 8;
            b[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        }
        b
    }

    #[test]
    fn is_allocated_walks_a_two_level_layout() {
        // The address array holds a CAB at block 1; the CAB lists a CIB at
        // block 2; the CIB's chunk has its bitmap at block 3.
        let mut bitmap = vec![0u8; BLK];
        bitmap[0] = 0b0000_1000; // block 3 of the chunk allocated
        let mut block = spaceman(32, 100, 32, 31, 1, &[1]);
        // cab_count = 1, cibs_per_cab = 10 on the main device.
        block[0x2C..0x30].copy_from_slice(&10u32.to_le_bytes());
        block[SM_DEV_OFFSET + 20..SM_DEV_OFFSET + 24].copy_from_slice(&1u32.to_le_bytes());
        let image: Vec<u8> = {
            let mut data = block;
            data.extend(cab(&[2])); // block 1: CAB -> CIB at block 2
            data.extend(cib(32, 31, 3)); // block 2: CIB -> bitmap at block 3
            data.extend(bitmap); // block 3
            data
        };
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        assert_eq!(sm.cibs_per_cab, 10);
        let mut reader = Cursor::new(image);
        assert!(sm.is_allocated(&mut reader, 3).unwrap());
        assert!(!sm.is_allocated(&mut reader, 0).unwrap());
    }

    #[test]
    fn free_extents_coalesce_and_sum_to_the_free_count() {
        // One 32-block chunk: blocks 0, 1, 8 allocated; 29 free.
        let mut bitmap = vec![0u8; BLK];
        bitmap[0] = 0b0000_0011; // blocks 0,1
        bitmap[1] = 0b0000_0001; // block 8
        let image: Vec<u8> = {
            let mut data = spaceman(32, 100, 32, 29, 1, &[1]);
            data.extend(cib(32, 29, 2)); // block 1
            data.extend(bitmap); // block 2
            data
        };
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        let extents = sm.free_extents(&mut reader).unwrap();
        // Free runs: [2,8) and [9,32).
        assert_eq!(
            extents,
            vec![
                FreeExtent {
                    start: 2,
                    length: 6
                },
                FreeExtent {
                    start: 9,
                    length: 23
                },
            ],
        );
        let total: u64 = extents.iter().map(|e| e.length).sum();
        assert_eq!(total, sm.main_device.free_count);
    }

    #[test]
    fn constants_match_their_documented_absolute_offsets() {
        // The on-disk constants are computed from `OBJ_PHYS_SIZE`. A mutation
        // that flips `+` to `*`/`-` here would silently move every other test
        // helper to the new offset too, so the round-trip cancels — hence the
        // mutants survive every layout-shaped test. Pinning the absolute
        // numeric values catches every flip independent of helper code.
        assert_eq!(SM_DEV_OFFSET, 48);
        assert_eq!(CIB_CHUNK_INFO_OFFSET, 40);
        assert_eq!(CAB_CIB_ADDR_OFFSET, 40);
        assert_eq!(CAB_CIB_COUNT_OFFSET, 36);
    }

    #[test]
    fn parse_reports_the_exact_minimum_size_when_truncated() {
        // A 143-byte block is one short of the `spaceman_phys_t` minimum.
        // The error must name the outer structure (so the parse-time guard
        // is what rejected it, not the per-device parser) and report
        // `expected = SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE = 144`.
        // Pins down line 127 (`< → ==`/`<=`) and line 130 (`+ → *`,
        // `* → +`/`/`): any of those flips would either change the
        // `expected` value or route the error through `parse_device` and
        // change `structure`.
        let block = vec![0u8; 143];
        match SpaceManager::parse(block) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "spaceman_phys_t");
                assert_eq!(expected, 144);
                assert_eq!(actual, 143);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_accepts_a_block_at_exactly_the_minimum_size() {
        // A 144-byte block holds the fixed `spaceman_phys_t` fields but no
        // address array. The `< MIN` guard must accept it (so `<` ↔ `<=` is
        // catchable). The device parses succeed because both per-device
        // slices fit exactly within the 144 bytes.
        let mut block = vec![0u8; 144];
        // Distinct nonzero block_size so we can confirm parsing happened.
        block[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        let sm = SpaceManager::parse(block).expect("144-byte block must parse");
        assert_eq!(sm.block_size, 4096);
    }

    #[test]
    fn parse_device_reports_the_exact_expected_offset_on_truncation() {
        // Build a 100-byte block that passes the outer length check is
        // impossible (we'd need ≥144), but `parse_device` is reachable from
        // a truncated outer block once the guard is bypassed in tests like
        // this. Call it directly so the line 106 `expected` value is pinned:
        // `expected = offset + SPACEMAN_DEVICE_SIZE`. Mutants `+ → -`/`*`
        // would report `48 - 48 = 0` or `48 * 48 = 2304`.
        let short = vec![0u8; 80];
        match parse_device(&short, 48) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "spaceman_device_t");
                assert_eq!(expected, 96);
                assert_eq!(actual, 80);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_places_tier2_after_the_main_device() {
        // Write distinct nonzero values into the tier-2 slot (offset 96).
        // The line 139 `+ → -` mutant parses tier-2 from offset 0 (over the
        // obj_phys header) and `+ → *` from offset 48*48 = 2304: in both
        // cases the tier-2 fields would not pick up the bytes we wrote at
        // offset 96. The line 24 `+ → *` mutant moves SM_DEV_OFFSET to 512
        // and tier-2 to 560, which also misses our nonzero bytes.
        let mut block = vec![0u8; BLK];
        block[0x20..0x24].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        // Main device at offset 48: block_count = 1000, free = 100.
        block[48..56].copy_from_slice(&1000u64.to_le_bytes());
        block[48 + 24..48 + 32].copy_from_slice(&100u64.to_le_bytes());
        // Tier-2 device at offset 96: block_count = 2000, free = 500.
        block[96..104].copy_from_slice(&2000u64.to_le_bytes());
        block[96 + 24..96 + 32].copy_from_slice(&500u64.to_le_bytes());
        let sm = SpaceManager::parse(block).unwrap();
        assert_eq!(sm.main_device.block_count, 1000);
        assert_eq!(sm.main_device.free_count, 100);
        assert_eq!(sm.tier2_device.block_count, 2000);
        assert_eq!(sm.tier2_device.free_count, 500);
        // Totals exercise the line 154/160 `+ → -` mutants directly.
        assert_eq!(sm.total_blocks(), 3000);
        assert_eq!(sm.free_blocks(), 600);
    }

    #[test]
    fn device_address_reads_the_indexed_entry() {
        // Place two distinct addresses in the main device's address array and
        // confirm `device_address(1)` returns the second one — not the first
        // (kills line 166 `-> Ok(1)` and line 167 `+ → -`, since with
        // index = 1 the two paths return different bytes).
        let mut block = vec![0u8; BLK];
        block[0x20..0x24].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        let addr_off = SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE;
        // Main device: addr_offset
        block[SM_DEV_OFFSET + 32..SM_DEV_OFFSET + 36].copy_from_slice(
            &u32::try_from(addr_off)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        block[addr_off..addr_off + 8].copy_from_slice(&0x1111_1111_u64.to_le_bytes());
        block[addr_off + 8..addr_off + 16].copy_from_slice(&0x2222_2222_u64.to_le_bytes());
        let sm = SpaceManager::parse(block).unwrap();
        assert_eq!(sm.device_address(0).unwrap(), 0x1111_1111);
        assert_eq!(sm.device_address(1).unwrap(), 0x2222_2222);
    }

    #[test]
    fn cib_address_walks_two_level_with_a_non_zero_cib_in_cab() {
        // Two-level layout with cibs_per_cab = 2 and a chunk_index that
        // lands at cib_index = 1 → cab_index = 0, cib_in_cab = 1. With
        // cib_in_cab = 1 the line 237 `+ → -` and `* → /` mutants change
        // the byte offset within the CAB; the line 215 `% → /` mutant
        // would return cib_in_cab = 0 and read the first slot instead.
        // chunks_per_cib = 4, cibs_per_cab = 2 → chunk_index = 4 selects
        // cib_index = 1, cab_index = 0, cib_in_cab = 1. cib_count = 2 so
        // the bounds check at line 195 passes.
        let mut block = spaceman(8, 4, 256, 0, 2, &[1]);
        // cab_count = 1, cibs_per_cab = 2 on the main device.
        block[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes());
        block[SM_DEV_OFFSET + 20..SM_DEV_OFFSET + 24].copy_from_slice(&1u32.to_le_bytes());
        // The address array's first entry is the CAB at block 1.
        // The CAB lists two CIBs: slot 0 → block 90 (decoy), slot 1 → block 2.
        // The CIB at block 2 reports chunk-in-cib = 0 fully allocated.
        let mut image = block;
        image.extend(cab(&[90, 2])); // block 1
        image.extend(cib(8, 0, 0)); // block 2: bitmapless full chunk
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        // chunk_index = 4 → cib_index = 1 → cab_index = 0, cib_in_cab = 1.
        // block_addr = chunk_index * blocks_per_chunk = 4*8 = 32.
        assert!(sm.is_allocated(&mut reader, 32).unwrap());
    }

    #[test]
    fn is_allocated_uses_a_non_zero_chunk_in_cib() {
        // chunks_per_cib = 2 with chunk_index = 1 forces chunk_in_cib = 1,
        // exposing line 249 (`% → /` would give 0) and line 251 (`* → /`
        // would aim at offset 40 + 1/32 = 40 instead of 40 + 32). The CIB
        // holds two chunk-info entries; slot 0 is decoy (every block
        // uniformly free), slot 1 marks every block allocated.
        let mut data = spaceman(8, 2, 16, 8, 1, &[1]);
        // The CIB at block 1 lists two chunk entries.
        let mut chunk_block = vec![0u8; BLK];
        chunk_block[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&2u32.to_le_bytes());
        // Slot 0: 8 blocks, 8 free, no bitmap (uniformly free).
        let s0 = CIB_CHUNK_INFO_OFFSET;
        chunk_block[s0 + 16..s0 + 20].copy_from_slice(&8u32.to_le_bytes());
        chunk_block[s0 + 20..s0 + 24].copy_from_slice(&8u32.to_le_bytes());
        // Slot 1: 8 blocks, 0 free, no bitmap (uniformly allocated).
        let s1 = CIB_CHUNK_INFO_OFFSET + CHUNK_INFO_SIZE;
        chunk_block[s1 + 16..s1 + 20].copy_from_slice(&8u32.to_le_bytes());
        chunk_block[s1 + 20..s1 + 24].copy_from_slice(&0u32.to_le_bytes());
        data.extend(chunk_block);
        // main_device.chunk_count must be ≥ 2 so chunk_index = 1 is valid.
        data[SM_DEV_OFFSET + 8..SM_DEV_OFFSET + 16].copy_from_slice(&2u64.to_le_bytes());
        let sm = SpaceManager::parse(data[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(data);
        // chunk_index = 0 (slot 0) → free.
        assert!(!sm.is_allocated(&mut reader, 0).unwrap());
        // chunk_index = 1 (slot 1) → allocated. Block_addr = 1*8 + 0 = 8.
        assert!(sm.is_allocated(&mut reader, 8).unwrap());
    }

    #[test]
    fn cib_address_division_is_distinct_from_modulus_and_multiplication() {
        // Use chunks_per_cib = 4 and chunk_index = 6 so cib_index = 1
        // (= 6/4). The line 214 `/ → %` mutant would give cib_index = 2,
        // `/ → *` would give cib_index = 24 — both miss the populated CIB
        // entry at slot 1 and are rejected (cib_count = 2). Provide a
        // single-level layout so the address array directly stores CIB
        // addresses.
        let mut block = spaceman(4, 4, 32, 0, 2, &[1, 5]); // 2 CIBs
        // main_device.chunk_count = 8 so chunk_index = 6 is in range.
        block[SM_DEV_OFFSET + 8..SM_DEV_OFFSET + 16].copy_from_slice(&8u64.to_le_bytes());
        let mut image = block;
        // Block 1: CIB for chunks 0..3 (chunk_in_cib = 0 fully free).
        image.extend(cib(4, 4, 0));
        // Need a block 2 (filler).
        image.extend(vec![0u8; BLK]);
        // Need a block 3, 4 (filler).
        image.extend(vec![0u8; BLK]);
        image.extend(vec![0u8; BLK]);
        // Block 5: CIB for chunks 4..7. Slot 2 (= 6%4) is allocated.
        let mut cib5 = vec![0u8; BLK];
        cib5[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&4u32.to_le_bytes());
        for slot in 0..4 {
            let ci = CIB_CHUNK_INFO_OFFSET + slot * CHUNK_INFO_SIZE;
            cib5[ci + 16..ci + 20].copy_from_slice(&4u32.to_le_bytes()); // block_count
            // Slot 2 (chunk_in_cib for chunk_index=6) is fully allocated.
            let free = if slot == 2 { 0u32 } else { 4u32 };
            cib5[ci + 20..ci + 24].copy_from_slice(&free.to_le_bytes());
        }
        image.extend(cib5);
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        // block_addr = chunk_index * blocks_per_chunk = 6 * 4 = 24.
        assert!(sm.is_allocated(&mut reader, 24).unwrap());
    }

    #[test]
    fn is_allocated_requires_both_conditions_for_uniformly_full_chunk() {
        // A bitmapless chunk reports "allocated" only when free_count == 0
        // *and* block_count != 0. The `&& → ||` mutant on line 291 would
        // report "allocated" for an unused (block_count = 0) entry — the
        // helper below builds exactly that pathological case.
        let mut data = spaceman(8, 100, 8, 8, 1, &[1]);
        // Chunk has block_count = 0, free_count = 8: under `&&`, returns
        // false (allocated requires free_count == 0). Under `||`, returns
        // true (block_count != 0 is true... wait, here block_count == 0).
        // We need the inputs that flip:
        // `(free == 0) && (block_count != 0)` → only true when both hold.
        // `(free == 0) || (block_count != 0)` → true if either holds.
        // To distinguish: pick free_count != 0 and block_count != 0 → AND
        // returns false (free != 0 fails); OR returns true (block_count
        // != 0 holds).
        let mut cib_block = vec![0u8; BLK];
        cib_block[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&1u32.to_le_bytes());
        let ci = CIB_CHUNK_INFO_OFFSET;
        cib_block[ci + 16..ci + 20].copy_from_slice(&8u32.to_le_bytes()); // block_count = 8
        cib_block[ci + 20..ci + 24].copy_from_slice(&3u32.to_le_bytes()); // free_count = 3
        // bitmap_addr = 0 → bitmapless branch.
        data.extend(cib_block);
        let sm = SpaceManager::parse(data[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(data);
        // Original: free != 0 → not uniformly allocated → returns false.
        assert!(!sm.is_allocated(&mut reader, 0).unwrap());
    }

    #[test]
    fn free_extents_accepts_a_bitmap_exactly_covering_its_chunk() {
        // Force `bitmap.len() * 8 == block_count` so the strict `<` boundary
        // matters: the original passes, but `< → ==` and `< → <=` would
        // reject the bitmap as "shorter than the chunk it covers". A chunk
        // of `BLK * 8` blocks is covered by exactly the whole `BLK`-sized
        // bitmap block.
        let chunk_blocks = u32::try_from(BLK).expect("the test fixture value fits in u32") * 8; // 32768
        let mut data = spaceman(chunk_blocks, 100, u64::from(chunk_blocks), 0, 1, &[1]);
        // Bitmapped chunk fully allocated, bitmap at block 2.
        let mut cib_block = vec![0u8; BLK];
        cib_block[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&1u32.to_le_bytes());
        let ci = CIB_CHUNK_INFO_OFFSET;
        cib_block[ci + 16..ci + 20].copy_from_slice(&chunk_blocks.to_le_bytes());
        cib_block[ci + 20..ci + 24].copy_from_slice(&0u32.to_le_bytes()); // free_count
        cib_block[ci + 24..ci + 32].copy_from_slice(&2i64.to_le_bytes()); // bitmap at block 2
        data.extend(cib_block);
        // Bitmap: every bit set → every block allocated → no free extents.
        data.extend(vec![0xFFu8; BLK]);
        let sm = SpaceManager::parse(data[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(data);
        let extents = sm.free_extents(&mut reader).unwrap();
        assert_eq!(extents, vec![]);
    }

    #[test]
    fn free_extents_coalesce_across_chunk_boundaries() {
        // Two bitmapless chunks of 16 blocks, both entirely free: the free
        // runs must merge into a single 32-block extent.
        let image: Vec<u8> = {
            let mut data = spaceman(16, 100, 32, 32, 1, &[1]);
            // One CIB holding two chunk-info entries, both bitmapless+free.
            let mut cib = vec![0u8; BLK];
            cib[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&2u32.to_le_bytes());
            for chunk in 0..2 {
                let ci = CIB_CHUNK_INFO_OFFSET + chunk * CHUNK_INFO_SIZE;
                cib[ci + 16..ci + 20].copy_from_slice(&16u32.to_le_bytes()); // block_count
                cib[ci + 20..ci + 24].copy_from_slice(&16u32.to_le_bytes()); // free_count
                // ci_bitmap_addr stays 0 — a uniformly free chunk.
            }
            data.extend(cib); // block 1
            data
        };
        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        let extents = sm.free_extents(&mut reader).unwrap();
        assert_eq!(
            extents,
            vec![FreeExtent {
                start: 0,
                length: 32
            }]
        );
    }
}
