//! Fusion-drive support — address markers, write-back cache, middle tree.
//!
//! A Fusion drive presents a solid-state drive and a hard drive as one APFS
//! container. Block addresses are tagged to select the device, and an SSD
//! write-back cache tracks blocks staged for the hard drive.
//!
//! Apple File System Reference, `19-fusion.md`.

use alloc::vec::Vec;

use bitflags::bitflags;

use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::object::OBJ_PHYS_SIZE;

/// Byte-address marker selecting the Fusion tier-2 (hard-drive) device
/// (`FUSION_TIER2_DEVICE_BYTE_ADDR`).
pub const FUSION_TIER2_DEVICE_BYTE_ADDR: u64 = 0x4000_0000_0000_0000;

/// Size of a `fusion_wbc_list_entry_t`.
const FUSION_WBC_LIST_ENTRY_SIZE: usize = 24;
/// Offset of the `fwlp_listEntries` array within `fusion_wbc_list_phys_t`.
const FUSION_WBC_LIST_ENTRIES_OFFSET: usize = OBJ_PHYS_SIZE + 8 + 8 + 4 * 4;

bitflags! {
    /// Fusion middle-tree flags (`FUSION_MT_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FusionMtFlags: u32 {
        /// The cached block is dirty (not yet written back to the hard drive).
        const DIRTY = 1 << 0;
        /// The block belongs to a tenant.
        const TENANT = 1 << 1;
    }
}

/// A decoded Fusion block address — which device, and the block on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusionAddress {
    /// Whether the address is on the tier-2 (hard-drive) device.
    pub tier2: bool,
    /// The block number on the selected device.
    pub block: u64,
}

/// The tier-2 block-address marker for a given block size.
///
/// A block address with this bit set refers to the hard drive.
#[must_use]
pub fn tier2_marker(block_size: u32) -> u64 {
    if block_size == 0 {
        return 0;
    }
    FUSION_TIER2_DEVICE_BYTE_ADDR >> block_size.trailing_zeros()
}

/// Decodes a Fusion-tagged block address into its device and block number.
#[must_use]
pub fn decode_address(addr: u64, block_size: u32) -> FusionAddress {
    let marker = tier2_marker(block_size);
    if marker != 0 && addr & marker != 0 {
        FusionAddress {
            tier2: true,
            block: addr & !marker,
        }
    } else {
        FusionAddress {
            tier2: false,
            block: addr,
        }
    }
}

/// A parsed Fusion write-back cache (`fusion_wbc_phys_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusionWbc {
    /// The write-back cache format version.
    pub version: u64,
    /// Object id of the first write-back-cache list.
    pub list_head_oid: u64,
    /// Object id of the last write-back-cache list.
    pub list_tail_oid: u64,
    /// Number of blocks the list chain occupies.
    pub list_blocks_count: u32,
}

impl FusionWbc {
    /// Parses a `fusion_wbc_phys_t` block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed-width write-back-cache field ceases to fit the
    /// minimum block length checked before parsing.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < OBJ_PHYS_SIZE + 56 {
            return Err(ApfsError::Truncated {
                structure: "fusion_wbc_phys_t",
                expected: OBJ_PHYS_SIZE + 56,
                actual: block.len(),
            });
        }
        let u64_at =
            |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().expect("8 bytes"));
        Ok(Self {
            version: u64_at(OBJ_PHYS_SIZE),
            list_head_oid: u64_at(OBJ_PHYS_SIZE + 8),
            list_tail_oid: u64_at(OBJ_PHYS_SIZE + 16),
            list_blocks_count: u32::from_le_bytes(
                block[OBJ_PHYS_SIZE + 40..OBJ_PHYS_SIZE + 44]
                    .try_into()
                    .expect("4 bytes"),
            ),
        })
    }
}

/// One write-back-cache mapping (`fusion_wbc_list_entry_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusionWbcEntry {
    /// Block address of the cached copy on the solid-state drive.
    pub wbc_lba: i64,
    /// Block address of the data's home on the hard drive.
    pub target_lba: i64,
    /// Length of the cached run, in blocks.
    pub length: u64,
}

impl FusionWbcEntry {
    /// Whether `target` falls within this entry's hard-drive run.
    #[must_use]
    pub fn covers(&self, target: i64) -> bool {
        // `target - target_lba` can overflow `i64` for a malformed entry
        // (e.g. `target_lba == i64::MIN`); a failed subtraction means the
        // target is not covered rather than a panic.
        let Some(delta) = target.checked_sub(self.target_lba) else {
            return false;
        };
        delta >= 0 && delta < i64::try_from(self.length).unwrap_or(i64::MAX)
    }
}

/// A parsed write-back-cache list block (`fusion_wbc_list_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionWbcList {
    /// The list's mappings.
    pub entries: Vec<FusionWbcEntry>,
}

impl FusionWbcList {
    /// Parses a `fusion_wbc_list_phys_t` block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] or [`ApfsError::Malformed`] when the
    /// declared entry count does not fit the block.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed-width list field ceases to fit the bounds
    /// validated before parsing.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < FUSION_WBC_LIST_ENTRIES_OFFSET {
            return Err(ApfsError::Truncated {
                structure: "fusion_wbc_list_phys_t",
                expected: FUSION_WBC_LIST_ENTRIES_OFFSET,
                actual: block.len(),
            });
        }
        // fwlp_indexBegin / fwlp_indexEnd bound the live entry range.
        let index_begin = u32::from_le_bytes(
            block[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        let index_end = u32::from_le_bytes(
            block[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        if index_end < index_begin {
            return Err(ApfsError::Malformed {
                structure: "fusion_wbc_list_phys_t",
                reason: "list end index precedes the begin index",
            });
        }
        let needed =
            FUSION_WBC_LIST_ENTRIES_OFFSET + index_end.saturating_mul(FUSION_WBC_LIST_ENTRY_SIZE);
        if needed > block.len() {
            return Err(ApfsError::Malformed {
                structure: "fusion_wbc_list_phys_t",
                reason: "list entry range exceeds the block",
            });
        }

        let mut entries = Vec::with_capacity(index_end - index_begin);
        for i in index_begin..index_end {
            let base = FUSION_WBC_LIST_ENTRIES_OFFSET + i * FUSION_WBC_LIST_ENTRY_SIZE;
            let i64_at = |off: usize| {
                i64::from_le_bytes(
                    block[base + off..base + off + 8]
                        .try_into()
                        .expect("8 bytes"),
                )
            };
            entries.push(FusionWbcEntry {
                wbc_lba: i64_at(0),
                target_lba: i64_at(8),
                length: u64::from_le_bytes(
                    block[base + 16..base + 24].try_into().expect("8 bytes"),
                ),
            });
        }
        Ok(Self { entries })
    }

    /// Resolves a hard-drive block to its cached solid-state copy, if any.
    #[must_use]
    pub fn cached_copy(&self, target_block: i64) -> Option<i64> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.covers(target_block))?;
        // `covers` already proved `target_block - target_lba` is in range;
        // saturate the SSD-side addition against a malformed `wbc_lba`.
        let delta = target_block - entry.target_lba;
        Some(entry.wbc_lba.saturating_add(delta))
    }
}

/// A parsed Fusion middle-tree value (`fusion_mt_val_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusionMtVal {
    /// Block address of the cached data.
    pub lba: i64,
    /// Length of the cached run, in blocks.
    pub length: u32,
    /// Middle-tree flags.
    pub flags: FusionMtFlags,
}

impl FusionMtVal {
    /// Parses a `fusion_mt_val_t` value (16 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short value.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed-width middle-tree field ceases to fit the
    /// minimum value length checked before parsing.
    pub fn parse(value: &[u8]) -> Result<Self> {
        if value.len() < 16 {
            return Err(ApfsError::Truncated {
                structure: "fusion_mt_val_t",
                expected: 16,
                actual: value.len(),
            });
        }
        Ok(Self {
            lba: i64::from_le_bytes(value[0..8].try_into().expect("8 bytes")),
            length: u32::from_le_bytes(value[8..12].try_into().expect("4 bytes")),
            flags: FusionMtFlags::from_bits_retain(u32::from_le_bytes(
                value[12..16].try_into().expect("4 bytes"),
            )),
        })
    }
}

/// A read-time map from tier-2 (hard-drive) blocks to their cached copies
/// on the main (solid-state) device.
///
/// Built from a volume's Fusion write-back cache; a [`FusionReader`]
/// consults it so a read of a cached hard-drive block is served from the
/// faster SSD copy, exactly as the live file system would.
#[derive(Debug, Clone, Default)]
pub struct FusionCache {
    /// `(tier2_start, main_start, length)` cached runs.
    runs: Vec<(u64, u64, u64)>,
}

impl FusionCache {
    /// Creates an empty cache — every tier-2 block reads from the
    /// hard-drive device.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a cached run: `length` blocks starting at hard-drive block
    /// `tier2_start` are mirrored from main-device block `main_start`.
    pub fn add_run(&mut self, tier2_start: u64, main_start: u64, length: u64) {
        if length != 0 {
            self.runs.push((tier2_start, main_start, length));
        }
    }

    /// Builds a cache from a write-back-cache list block.
    ///
    /// Each [`FusionWbcEntry`] maps a hard-drive run (`target_lba`) to its
    /// solid-state copy (`wbc_lba`); a negative address is skipped.
    #[must_use]
    pub fn from_wbc_list(list: &FusionWbcList) -> Self {
        let mut cache = Self::new();
        for entry in &list.entries {
            if let (Ok(tier2), Ok(main)) = (
                u64::try_from(entry.target_lba),
                u64::try_from(entry.wbc_lba),
            ) {
                cache.add_run(tier2, main, entry.length);
            }
        }
        cache
    }

    /// The main-device block holding the cached copy of `tier2_block`, if
    /// the hard-drive block is currently cached.
    #[must_use]
    pub fn cached_block(&self, tier2_block: u64) -> Option<u64> {
        for &(tier2_start, main_start, length) in &self.runs {
            // Runs are stored in write-back-list order (by recency), not
            // sorted by `tier2_start`; a block below this run's start may
            // still fall in a later run, so skip rather than give up.
            let Some(offset) = tier2_block.checked_sub(tier2_start) else {
                continue;
            };
            if offset < length {
                return main_start.checked_add(offset);
            }
        }
        None
    }
}

/// A read-only view over a Fusion container's two physical devices.
///
/// A Fusion container spans a fast solid-state device and a slower hard
/// drive; block addresses are tagged to select the device (see
/// [`decode_address`]). `FusionReader` implements [`Read`] + [`Seek`] over
/// the tagged address space the rest of the crate already computes, so an
/// `Apfs` mounted on it resolves every block to the correct device — and a
/// hard-drive block present in the write-back cache to its SSD copy —
/// without any change to the single-reader path used for non-Fusion
/// containers.
pub struct FusionReader<M, T2> {
    main: M,
    tier2: Option<T2>,
    block_size: u32,
    cache: FusionCache,
    pos: u64,
}

impl<M: Read + Seek, T2: Read + Seek> FusionReader<M, T2> {
    /// Creates a Fusion reader over the `main` (solid-state) device and an
    /// optional `tier2` (hard-drive) device.
    ///
    /// A container whose data never references the hard drive can be read
    /// with `tier2` absent; a tier-2 read with no hard-drive reader then
    /// fails with a typed error rather than returning wrong bytes.
    #[must_use]
    pub fn new(main: M, tier2: Option<T2>, block_size: u32, cache: FusionCache) -> Self {
        Self {
            main,
            tier2,
            block_size,
            cache,
            pos: 0,
        }
    }
}

impl<M: Read + Seek, T2: Read + Seek> Read for FusionReader<M, T2> {
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            // A zero block size cannot map an address to a device.
            return Err(crate::io::ErrorKind::InvalidInput.into());
        }
        let block = self.pos / block_size;
        let intra = self.pos % block_size;
        let decoded = decode_address(block, self.block_size);

        // Route the read: a tier-2 block goes to the hard drive unless the
        // write-back cache holds an SSD copy, which lives on the main device.
        let (real_block, from_tier2) = if decoded.tier2 {
            match self.cache.cached_block(decoded.block) {
                Some(cached) => (cached, false),
                None => (decoded.block, true),
            }
        } else {
            (decoded.block, false)
        };
        // A device address that overflows `u64` is structurally invalid.
        let real_offset = real_block
            .checked_mul(block_size)
            .and_then(|base| base.checked_add(intra))
            .ok_or(crate::io::Error::from(crate::io::ErrorKind::InvalidData))?;

        // Serve at most to the end of the current block, so each read is
        // routed to a single device.
        let span = usize::try_from(block_size - intra).unwrap_or(usize::MAX);
        let want = buf.len().min(span);
        let read = if from_tier2 {
            // The address references the hard drive, but no tier-2 reader
            // was supplied — fail loudly rather than read wrong bytes.
            let tier2 = self
                .tier2
                .as_mut()
                .ok_or(crate::io::Error::from(crate::io::ErrorKind::InvalidData))?;
            tier2.seek(SeekFrom::Start(real_offset))?;
            tier2.read(&mut buf[..want])?
        } else {
            self.main.seek(SeekFrom::Start(real_offset))?;
            self.main.read(&mut buf[..want])?
        };
        self.pos += read as u64;
        Ok(read)
    }
}

impl<M: Read + Seek, T2: Read + Seek> Seek for FusionReader<M, T2> {
    fn seek(&mut self, pos: SeekFrom) -> crate::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => self
                .pos
                .checked_add_signed(delta)
                .ok_or(crate::io::Error::from(crate::io::ErrorKind::InvalidInput))?,
            // A Fusion container has no single end offset — the two devices
            // occupy disjoint regions of the tagged address space.
            SeekFrom::End(_) => return Err(crate::io::ErrorKind::InvalidInput.into()),
        };
        self.pos = target;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_marker_decodes_the_device() {
        // With 4 KiB blocks the tier-2 marker is bit 50.
        let marker = tier2_marker(4096);
        assert_eq!(marker, FUSION_TIER2_DEVICE_BYTE_ADDR >> 12);

        let main = decode_address(1234, 4096);
        assert!(!main.tier2);
        assert_eq!(main.block, 1234);

        let tier2 = decode_address(marker | 0x04D2, 4096);
        assert!(tier2.tier2);
        assert_eq!(tier2.block, 1234);
    }

    #[test]
    fn parses_a_write_back_cache() {
        let mut b = vec![0u8; OBJ_PHYS_SIZE + 56];
        b[OBJ_PHYS_SIZE + 8..OBJ_PHYS_SIZE + 16].copy_from_slice(&77u64.to_le_bytes());
        b[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 24].copy_from_slice(&88u64.to_le_bytes());
        b[OBJ_PHYS_SIZE + 40..OBJ_PHYS_SIZE + 44].copy_from_slice(&9u32.to_le_bytes());
        let wbc = FusionWbc::parse(&b).unwrap();
        assert_eq!(wbc.list_head_oid, 77);
        // `list_tail_oid` lives at OBJ_PHYS_SIZE + 16; a `-` for `+` typo on
        // the offset would read it from the wrong place.
        assert_eq!(wbc.list_tail_oid, 88);
        assert_eq!(wbc.list_blocks_count, 9);
    }

    #[test]
    fn fusion_wbc_reports_full_expected_size_on_truncation() {
        // The Truncated error must declare the full prefix size; an
        // arithmetic typo (`*` for `+`) would report a wildly different
        // expected length and downstream tooling can no longer trust it.
        let err = FusionWbc::parse(&[0u8; 16]).unwrap_err();
        match err {
            ApfsError::Truncated {
                structure,
                expected,
                actual,
            } => {
                assert_eq!(structure, "fusion_wbc_phys_t");
                assert_eq!(expected, OBJ_PHYS_SIZE + 56);
                assert_eq!(actual, 16);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn write_back_cache_list_resolves_a_cached_block() {
        // One entry: hard-drive blocks 200..210 cached at SSD blocks 50..60.
        let mut b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET + FUSION_WBC_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24].copy_from_slice(&1u32.to_le_bytes()); // index_end
        let base = FUSION_WBC_LIST_ENTRIES_OFFSET;
        b[base..base + 8].copy_from_slice(&50i64.to_le_bytes()); // wbc_lba
        b[base + 8..base + 16].copy_from_slice(&200i64.to_le_bytes()); // target_lba
        b[base + 16..base + 24].copy_from_slice(&10u64.to_le_bytes()); // length
        let list = FusionWbcList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.cached_copy(205), Some(55));
        // The boundary blocks pin the half-open range — `cached_copy` must
        // refuse `target_lba + length` even though `target_lba + length - 1`
        // succeeds, ruling out an inclusive upper bound.
        assert_eq!(list.cached_copy(209), Some(59));
        assert_eq!(list.cached_copy(210), None);
        assert_eq!(list.cached_copy(999), None);
    }

    #[test]
    fn write_back_cache_list_parses_two_entries_at_distinct_offsets() {
        // Two entries with distinct values: a `-` for `+` on the entry base
        // computation would read entry 1 from a non-entry region (or
        // underflow), and a `/` for `*` on the per-entry stride would read
        // entry 1 from the same place as entry 0.
        let mut b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET + 2 * FUSION_WBC_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24].copy_from_slice(&2u32.to_le_bytes()); // index_end

        let e0 = FUSION_WBC_LIST_ENTRIES_OFFSET;
        b[e0..e0 + 8].copy_from_slice(&50i64.to_le_bytes());
        b[e0 + 8..e0 + 16].copy_from_slice(&200i64.to_le_bytes());
        b[e0 + 16..e0 + 24].copy_from_slice(&4u64.to_le_bytes());

        let e1 = FUSION_WBC_LIST_ENTRIES_OFFSET + FUSION_WBC_LIST_ENTRY_SIZE;
        b[e1..e1 + 8].copy_from_slice(&77i64.to_le_bytes());
        b[e1 + 8..e1 + 16].copy_from_slice(&900i64.to_le_bytes());
        b[e1 + 16..e1 + 24].copy_from_slice(&3u64.to_le_bytes());

        let list = FusionWbcList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.entries[0].wbc_lba, 50);
        assert_eq!(list.entries[0].target_lba, 200);
        assert_eq!(list.entries[0].length, 4);
        assert_eq!(list.entries[1].wbc_lba, 77);
        assert_eq!(list.entries[1].target_lba, 900);
        assert_eq!(list.entries[1].length, 3);
    }

    #[test]
    fn write_back_cache_list_accepts_equal_begin_and_end_indices() {
        // `index_begin == index_end` is an empty live range, not malformed:
        // a `<=` for `<` flip on the precedence check would reject it.
        let mut b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET + FUSION_WBC_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20].copy_from_slice(&1u32.to_le_bytes());
        b[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24].copy_from_slice(&1u32.to_le_bytes());
        let list = FusionWbcList::parse(&b).unwrap();
        assert!(list.entries.is_empty());
    }

    #[test]
    fn write_back_cache_list_parses_at_the_exact_prefix_boundary() {
        // A block of exactly `FUSION_WBC_LIST_ENTRIES_OFFSET` bytes with no
        // entries must parse; this pins the truncation check to strict
        // less-than and rules out an equality or less-than-or-equal flip.
        let b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET];
        let list = FusionWbcList::parse(&b).unwrap();
        assert!(list.entries.is_empty());
    }

    #[test]
    fn write_back_cache_list_rejects_an_oversized_index_end() {
        // An `index_end` that overruns the block must be reported as
        // Malformed. A `-` for `+` on the `needed` calculation would
        // underflow and treat every valid block as out of bounds, so the
        // companion "exactly-fits" case (the bare prefix above) pins the
        // direction: this case pins the comparison itself.
        let mut b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET + FUSION_WBC_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24].copy_from_slice(&5u32.to_le_bytes());
        assert!(matches!(
            FusionWbcList::parse(&b),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn write_back_cache_list_entries_live_at_documented_offset_64() {
        // The `fwlp_listEntries` array starts 64 bytes into the block
        // (`obj_phys_t` = 32, plus 4 × `u64` fields = 32). This test uses
        // literal offsets so an arithmetic typo on the offset constant
        // shifts the parser's read away from the bytes the test wrote,
        // without the test also moving (every other test sizes its buffer
        // and base from the constant, masking the mutation).
        const ENTRY_OFFSET: usize = 64;
        const BLOCK_LEN: usize = 200;
        let mut b = vec![0u8; BLOCK_LEN];
        // `fwlp_indexEnd` lives at OBJ_PHYS_SIZE + 20 = 52.
        b[52..56].copy_from_slice(&1u32.to_le_bytes());
        // Entry 0's three fields, at the documented byte offsets.
        b[ENTRY_OFFSET..ENTRY_OFFSET + 8].copy_from_slice(&123_456i64.to_le_bytes());
        b[ENTRY_OFFSET + 8..ENTRY_OFFSET + 16].copy_from_slice(&999_888i64.to_le_bytes());
        b[ENTRY_OFFSET + 16..ENTRY_OFFSET + 24].copy_from_slice(&7u64.to_le_bytes());

        let list = FusionWbcList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.entries[0].wbc_lba, 123_456);
        assert_eq!(list.entries[0].target_lba, 999_888);
        assert_eq!(list.entries[0].length, 7);
    }

    #[test]
    fn write_back_cache_list_parses_a_large_entry_count() {
        // Three entries — large enough that a `-` for `+` on the `needed`
        // calculation (`OFFSET - count * ENTRY_SIZE`) underflows and
        // produces a Malformed error on a buffer that should parse cleanly.
        let count = 3usize;
        let mut b = vec![0u8; FUSION_WBC_LIST_ENTRIES_OFFSET + count * FUSION_WBC_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 20..OBJ_PHYS_SIZE + 24].copy_from_slice(
            &u32::try_from(count)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        for i in 0..count {
            let off = FUSION_WBC_LIST_ENTRIES_OFFSET + i * FUSION_WBC_LIST_ENTRY_SIZE;
            let fixture_lba = i64::try_from(i).expect("the test fixture index fits in i64") + 1;
            b[off..off + 8].copy_from_slice(&fixture_lba.to_le_bytes());
            b[off + 8..off + 16].copy_from_slice(&(fixture_lba * 100).to_le_bytes());
            b[off + 16..off + 24].copy_from_slice(&1u64.to_le_bytes());
        }
        let list = FusionWbcList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), count);
        for (i, entry) in list.entries.iter().enumerate() {
            let expected_lba = i64::try_from(i).expect("the test fixture index fits in i64") + 1;
            assert_eq!(entry.wbc_lba, expected_lba);
            assert_eq!(entry.target_lba, expected_lba * 100);
        }
    }

    #[test]
    fn covers_does_not_overflow_on_extreme_target_lba() {
        // target_lba == i64::MIN makes `target - target_lba` overflow i64.
        let entry = FusionWbcEntry {
            wbc_lba: 0,
            target_lba: i64::MIN,
            length: 10,
        };
        assert!(!entry.covers(0));
        assert!(!entry.covers(i64::MAX));
    }

    #[test]
    fn covers_is_a_strict_half_open_range() {
        // A run of length 10 starting at 200 covers 200..210 — the upper
        // bound is exclusive. With the bound flipped to inclusive the run
        // would claim block 210, which actually belongs to the next run.
        let entry = FusionWbcEntry {
            wbc_lba: 50,
            target_lba: 200,
            length: 10,
        };
        assert!(entry.covers(200)); // first block
        assert!(entry.covers(209)); // last block
        assert!(!entry.covers(210)); // first block past the run
    }

    #[test]
    fn parses_a_middle_tree_value() {
        let mut value = vec![0u8; 16];
        value[0..8].copy_from_slice(&4096i64.to_le_bytes());
        value[8..12].copy_from_slice(&8u32.to_le_bytes());
        value[12..16].copy_from_slice(&FusionMtFlags::DIRTY.bits().to_le_bytes());
        let mt = FusionMtVal::parse(&value).unwrap();
        assert_eq!(mt.lba, 4096);
        assert_eq!(mt.length, 8);
        assert!(mt.flags.contains(FusionMtFlags::DIRTY));
    }

    #[test]
    fn short_inputs_are_rejected() {
        assert!(matches!(
            FusionWbc::parse(&[0u8; 16]),
            Err(ApfsError::Truncated { .. })
        ));
        assert!(matches!(
            FusionMtVal::parse(&[0u8; 8]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    // --- Multi-device reader ----------------------------------------------

    use fsmnt_testkit::Cursor;

    const BS: u32 = 4096;

    /// A device image of `blocks` blocks, with block `mark` filled `byte`.
    fn device(blocks: u64, mark: u64, byte: u8) -> Cursor<Vec<u8>> {
        let mut data = vec![
            0u8;
            usize::try_from(blocks * u64::from(BS))
                .expect("the test fixture value fits in usize")
        ];
        let start =
            usize::try_from(mark * u64::from(BS)).expect("the test fixture value fits in usize");
        data[start..start + BS as usize].fill(byte);
        Cursor::new(data)
    }

    /// Reads block `tagged` (a Fusion-tagged block number) in full.
    fn read_block<M: Read + Seek, T2: Read + Seek>(
        fr: &mut FusionReader<M, T2>,
        tagged: u64,
    ) -> Vec<u8> {
        fr.seek(SeekFrom::Start(tagged * u64::from(BS))).unwrap();
        let mut buf = vec![0u8; BS as usize];
        let n = fr.read(&mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn fusion_cache_maps_a_cached_run() {
        let list = FusionWbcList {
            entries: vec![FusionWbcEntry {
                wbc_lba: 200,    // SSD copy
                target_lba: 900, // hard-drive home
                length: 4,
            }],
        };
        let cache = FusionCache::from_wbc_list(&list);
        assert_eq!(cache.cached_block(900), Some(200));
        assert_eq!(cache.cached_block(903), Some(203));
        assert_eq!(cache.cached_block(904), None); // past the run
        assert_eq!(cache.cached_block(50), None);
    }

    #[test]
    fn cached_block_checks_runs_after_a_higher_start() {
        // Runs are not sorted by tier2_start — a write-back list orders
        // them by recency. A block covered by a later, lower-start run
        // must still resolve rather than being lost to an early return.
        let mut cache = FusionCache::new();
        cache.add_run(900, 200, 4); // tier-2 900..904 cached at SSD 200..204
        cache.add_run(100, 50, 4); // tier-2 100..104 cached at SSD 50..54
        assert_eq!(cache.cached_block(102), Some(52));
        assert_eq!(cache.cached_block(901), Some(201));
        assert_eq!(cache.cached_block(500), None);
    }

    #[test]
    fn fusion_reader_routes_to_the_tagged_device() {
        let main = device(4, 2, 0xAA);
        let tier2 = device(5, 3, 0xBB);
        let mut fr = FusionReader::new(main, Some(tier2), BS, FusionCache::new());

        // An untagged address reads from the main (solid-state) device.
        assert!(read_block(&mut fr, 2).iter().all(|&b| b == 0xAA));
        // A tier-2-tagged address reads from the hard-drive device.
        let tagged = tier2_marker(BS) | 3;
        assert!(read_block(&mut fr, tagged).iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn fusion_reader_serves_a_cached_block_from_the_ssd() {
        // Hard-drive block 3 is cached at main-device block 2.
        let main = device(4, 2, 0xAA);
        let tier2 = device(5, 3, 0xBB);
        let mut cache = FusionCache::new();
        cache.add_run(3, 2, 1);
        let mut fr = FusionReader::new(main, Some(tier2), BS, cache);

        // The tier-2-tagged read resolves to the SSD copy, not the drive.
        let tagged = tier2_marker(BS) | 3;
        assert!(read_block(&mut fr, tagged).iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn fusion_reader_without_a_tier2_device_errors_on_a_tier2_read() {
        let main = device(4, 2, 0xAA);
        let mut fr: FusionReader<_, Cursor<Vec<u8>>> =
            FusionReader::new(main, None, BS, FusionCache::new());
        // A main-device read still works.
        assert!(read_block(&mut fr, 2).iter().all(|&b| b == 0xAA));
        // A tier-2 read with no hard-drive reader fails loudly.
        fr.seek(SeekFrom::Start((tier2_marker(BS) | 3) * u64::from(BS)))
            .unwrap();
        assert!(fr.read(&mut [0u8; BS as usize]).is_err());
    }

    #[test]
    fn fusion_reader_caps_a_mid_block_read_at_the_block_end() {
        // Reading from the middle of block 1 must not spill into block 2:
        // the per-call span is `block_size - intra`, so a `+` for `-` typo
        // would over-report the available bytes and read across a block
        // boundary that may belong to a different device.
        let mut data = vec![0u8; 3 * BS as usize];
        // Block 1: all 0xAA.
        data[BS as usize..2 * BS as usize].fill(0xAA);
        // Block 2: all 0xBB — must not appear in the truncated read.
        data[2 * BS as usize..3 * BS as usize].fill(0xBB);
        let main = Cursor::new(data);
        let mut fr: FusionReader<_, Cursor<Vec<u8>>> =
            FusionReader::new(main, None, BS, FusionCache::new());

        let intra: u64 = 100;
        fr.seek(SeekFrom::Start(u64::from(BS) + intra)).unwrap();
        // Ask for far more than the rest of the block; the implementation
        // must cap at `BS - intra` bytes.
        let mut buf = vec![0u8; 2 * BS as usize];
        let n = fr.read(&mut buf).unwrap();
        assert_eq!(n as u64, u64::from(BS) - intra);
        assert!(buf[..n].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn fusion_reader_advances_position_by_bytes_read() {
        // `self.pos += read` must accumulate; a `-=` typo would underflow
        // on the very first read, and a `*=` typo would leave `pos` stuck
        // at zero. We seek to a known offset, read twice, and confirm the
        // position advances by exactly the number of bytes returned.
        let main = device(4, 0, 0xCC);
        let mut fr: FusionReader<_, Cursor<Vec<u8>>> =
            FusionReader::new(main, None, BS, FusionCache::new());

        let start: u64 = 200;
        fr.seek(SeekFrom::Start(start)).unwrap();
        let mut buf = [0u8; 64];
        let read1 = fr.read(&mut buf).unwrap();
        assert_eq!(read1, 64);
        assert_eq!(fr.stream_position().unwrap(), start + 64);

        let read2 = fr.read(&mut buf).unwrap();
        assert_eq!(read2, 64);
        assert_eq!(fr.stream_position().unwrap(), start + 128);
    }
}
