//! Data streams and file extents — reading file content.
//!
//! A file's content is a *data stream*: a [`DataStream`] (`j_dstream_t`)
//! recording its logical size, plus `FILE_EXTENT` records mapping logical
//! offsets to physical block extents.
//!
//! Apple File System Reference, `09-data-streams.md`.

use alloc::vec::Vec;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, U64, Unaligned};

use crate::catalog::{Catalog, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek, SeekFrom};

/// Mask selecting the byte length of a file extent (`J_FILE_EXTENT_LEN_MASK`).
pub const J_FILE_EXTENT_LEN_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
/// Size of a `j_dstream_t`.
pub const J_DSTREAM_SIZE: usize = 40;
/// Size of a `j_file_extent_key_t` (`j_key_t` + `logical_addr`).
pub const J_FILE_EXTENT_KEY_SIZE: usize = J_KEY_SIZE + 8;

/// On-disk `j_dstream_t` (40 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDstream {
    size: U64<LE>,
    alloced_size: U64<LE>,
    default_crypto_id: U64<LE>,
    total_bytes_written: U64<LE>,
    total_bytes_read: U64<LE>,
}

/// On-disk `j_file_extent_val_t` (24 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawFileExtentVal {
    len_and_flags: U64<LE>,
    phys_block_num: U64<LE>,
    crypto_id: U64<LE>,
}

/// A parsed data stream (`j_dstream_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataStream {
    /// Logical size of the data, in bytes.
    pub size: u64,
    /// Total space allocated for the data stream, in bytes.
    pub alloced_size: u64,
    /// Default encryption key or tweak identifier for the stream's extents.
    pub default_crypto_id: u64,
    /// Total bytes ever written to the stream.
    pub total_bytes_written: u64,
    /// Total bytes ever read from the stream.
    pub total_bytes_read: u64,
}

impl DataStream {
    /// Parses a `j_dstream_t` (typically the `INO_EXT_TYPE_DSTREAM` extended
    /// field of an inode).
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (raw, _rest) =
            RawDstream::ref_from_prefix(bytes).map_err(|_| ApfsError::Truncated {
                structure: "j_dstream_t",
                expected: J_DSTREAM_SIZE,
                actual: bytes.len(),
            })?;
        Ok(Self {
            size: raw.size.get(),
            alloced_size: raw.alloced_size.get(),
            default_crypto_id: raw.default_crypto_id.get(),
            total_bytes_written: raw.total_bytes_written.get(),
            total_bytes_read: raw.total_bytes_read.get(),
        })
    }
}

/// One file extent — a contiguous run of a file's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileExtent {
    /// Offset of this extent within the file's logical data, in bytes.
    pub logical_addr: u64,
    /// Length of the extent, in bytes (a multiple of the block size).
    pub length: u64,
    /// Physical block address the extent's data starts at.
    pub phys_block_num: u64,
    /// Encryption key or tweak identifier for this extent.
    pub crypto_id: u64,
}

impl FileExtent {
    /// Whether `offset` (a file-logical byte offset) falls inside this extent.
    #[must_use]
    pub fn contains(&self, offset: u64) -> bool {
        // `logical_addr + length` can overflow `u64` for a malformed extent;
        // saturate so a bad record misses cleanly rather than panicking.
        offset >= self.logical_addr && offset < self.logical_addr.saturating_add(self.length)
    }
}

/// A file's content: its logical size and the extents backing it.
#[derive(Debug, Clone)]
pub struct File {
    size: u64,
    extents: Vec<FileExtent>,
}

impl File {
    /// Builds a file handle for `obj_id` by collecting its `FILE_EXTENT`
    /// records from the catalog.
    ///
    /// `size` is the logical file size from the inode's data stream.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and parsing errors.
    pub fn open<T: Read + Seek>(
        catalog: &Catalog,
        reader: &mut T,
        obj_id: u64,
        size: u64,
    ) -> Result<Self> {
        let mut extents = Vec::new();
        catalog.visit_records_for(reader, obj_id, |header, key, value| {
            if header.kind == JObjType::FileExtent {
                extents.push(parse_file_extent(key, value)?);
            }
            Ok(())
        })?;
        extents.sort_by_key(|extent| extent.logical_addr);
        Ok(Self { size, extents })
    }

    /// Builds a file handle from extents already resolved elsewhere.
    ///
    /// Used for a sealed volume, whose file extents come from the
    /// file-extent tree (`apfs_fext_tree_oid`) rather than catalog
    /// `FILE_EXTENT` records.
    #[must_use]
    pub fn from_extents(size: u64, mut extents: Vec<FileExtent>) -> Self {
        extents.sort_by_key(|extent| extent.logical_addr);
        Self { size, extents }
    }

    /// The file's logical size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The file's extents, sorted by logical offset.
    #[must_use]
    pub fn extents(&self) -> &[FileExtent] {
        &self.extents
    }

    /// Reads file content starting at logical byte `offset` into `buf`.
    ///
    /// Returns the number of bytes read, which is short at end-of-file.
    /// Logical regions with no backing extent — holes in a sparse file — read
    /// as zeros.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors and [`ApfsError::Malformed`] for an extent that
    /// points outside the container.
    pub fn read_at<T: Read + Seek>(
        &self,
        reader: &mut T,
        block_size: u32,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let to_read = buf
            .len()
            .min(usize::try_from(self.size - offset).unwrap_or(usize::MAX));
        let mut done = 0usize;
        let mut extent_index = extent_index_at_or_after(&self.extents, offset);
        while keep_reading(done, to_read) {
            let pos = offset + done as u64;
            while let Some(extent) = self.extents.get(extent_index)
                && extent.logical_addr <= pos
                && !extent.contains(pos)
            {
                extent_index += 1;
            }
            let chunk = if let Some(extent) = self
                .extents
                .get(extent_index)
                .filter(|extent| extent.contains(pos))
            {
                let within = pos - extent.logical_addr;
                let extent_remaining = extent.length - within;
                let chunk =
                    (to_read - done).min(usize::try_from(extent_remaining).unwrap_or(usize::MAX));
                let byte_addr = extent
                    .phys_block_num
                    .checked_mul(u64::from(block_size))
                    .and_then(|base| base.checked_add(within))
                    .ok_or(ApfsError::Malformed {
                        structure: "j_file_extent_val_t",
                        reason: "extent address overflows the device",
                    })?;
                reader.seek(SeekFrom::Start(byte_addr))?;
                reader.read_exact(&mut buf[done..done + chunk])?;
                chunk
            } else {
                // A hole: zero-fill up to the next extent or the read end.
                let next = self
                    .extents
                    .get(extent_index)
                    .map_or(self.size, |extent| extent.logical_addr);
                let chunk = (to_read - done).min(usize::try_from(next - pos).unwrap_or(usize::MAX));
                buf[done..done + chunk].fill(0);
                chunk
            };
            if chunk == 0 {
                break;
            }
            done = advance_read_cursor(done, chunk);
        }
        Ok(done)
    }

    /// Reads the file's entire content into a new buffer.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`File::read_at`], and returns
    /// [`ApfsError::Malformed`] when the logical file size cannot be addressed
    /// on the host — rather than attempting a `usize::MAX` allocation.
    pub fn read_all<T: Read + Seek>(&self, reader: &mut T, block_size: u32) -> Result<Vec<u8>> {
        let len = usize::try_from(self.size).map_err(|_| ApfsError::Malformed {
            structure: "j_dstream_t",
            reason: "logical file size exceeds the addressable range",
        })?;
        let mut buf = alloc::vec![0u8; len];
        let read = self.read_at(reader, block_size, 0, &mut buf)?;
        buf.truncate(read);
        Ok(buf)
    }
}

/// Loop predicate for [`File::read_at`].
///
/// Extracted so the equivalent `<` → `<=` mutant can be suppressed without
/// hiding the other operator mutants in `read_at`: when `done == to_read`,
/// the loop body would compute `chunk = (to_read - done).min(...) = 0` and
/// break immediately, so both predicates have the same observable effect.
#[cfg_attr(test, mutants::skip)]
#[inline]
fn keep_reading(done: usize, to_read: usize) -> bool {
    done < to_read
}

/// Finds the extent containing `pos`, or the first extent after it.
///
/// The caller advances from this point monotonically, making a ranged read
/// `O(log n + k)` for `n` total extents and `k` extents crossed.
#[cfg_attr(test, mutants::skip)]
fn extent_index_at_or_after(extents: &[FileExtent], pos: u64) -> usize {
    extents
        .partition_point(|extent| extent.logical_addr <= pos)
        .saturating_sub(1)
}

/// Advances [`File::read_at`]'s byte cursor by `chunk` (which is `> 0`).
///
/// Extracted so the `+ → *` mutant — which would keep `done` at zero and
/// loop forever — can be suppressed without hiding the other operator
/// mutants in `read_at`. The infinite loop is otherwise detected only by the
/// 20s test-runner cap.
#[cfg_attr(test, mutants::skip)]
#[inline]
fn advance_read_cursor(done: usize, chunk: usize) -> usize {
    done + chunk
}

/// Parses a `FILE_EXTENT` record into a [`FileExtent`].
pub(crate) fn parse_file_extent(key: &[u8], value: &[u8]) -> Result<FileExtent> {
    let logical = key
        .get(J_KEY_SIZE..J_KEY_SIZE + 8)
        .ok_or(ApfsError::Truncated {
            structure: "j_file_extent_key_t",
            expected: J_FILE_EXTENT_KEY_SIZE,
            actual: key.len(),
        })?;
    let logical_addr = u64::from_le_bytes(logical.try_into().expect("8 bytes"));

    let (raw, _rest) =
        RawFileExtentVal::ref_from_prefix(value).map_err(|_| ApfsError::Truncated {
            structure: "j_file_extent_val_t",
            expected: core::mem::size_of::<RawFileExtentVal>(),
            actual: value.len(),
        })?;
    Ok(FileExtent {
        logical_addr,
        length: raw.len_and_flags.get() & J_FILE_EXTENT_LEN_MASK,
        phys_block_num: raw.phys_block_num.get(),
        crypto_id: raw.crypto_id.get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::object::OBJ_PHYSICAL;
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use fsmnt_testkit::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn parses_a_data_stream() {
        let mut bytes = vec![0u8; J_DSTREAM_SIZE];
        bytes[0..8].copy_from_slice(&8192u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&8192u64.to_le_bytes());
        let ds = DataStream::parse(&bytes).unwrap();
        assert_eq!(ds.size, 8192);
        assert_eq!(ds.alloced_size, 8192);
    }

    #[test]
    fn data_stream_rejects_short_buffer() {
        assert!(matches!(
            DataStream::parse(&[0u8; 10]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn file_extent_contains_does_not_overflow() {
        // logical_addr + length wraps u64; contains must not panic.
        let extent = FileExtent {
            logical_addr: u64::MAX - 10,
            length: 4096,
            phys_block_num: 0,
            crypto_id: 0,
        };
        assert!(extent.contains(u64::MAX - 5));
        assert!(!extent.contains(0));
    }

    #[test]
    fn file_extent_parses_length_masking_off_flags() {
        let key = {
            let mut k = vec![0u8; J_KEY_SIZE];
            k.extend_from_slice(&4096u64.to_le_bytes()); // logical_addr
            k
        };
        let mut value = vec![0u8; 24];
        // length 4096 with a flag byte set in the high bits.
        value[0..8].copy_from_slice(&(0x0500_0000_0000_1000u64).to_le_bytes());
        value[8..16].copy_from_slice(&7u64.to_le_bytes()); // phys_block_num
        let extent = parse_file_extent(&key, &value).unwrap();
        assert_eq!(extent.logical_addr, 4096);
        assert_eq!(extent.length, 4096);
        assert_eq!(extent.phys_block_num, 7);
    }

    // --- File content reading against a synthetic volume ------------------

    fn omap_phys(tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes());
        b[0x30..0x38].copy_from_slice(&tree_oid.to_le_bytes());
        b
    }

    fn omap_tree(node_oid: u64, node_paddr: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
        b[0x2A..0x2C].copy_from_slice(&4u16.to_le_bytes());
        let key_area = BTN_DATA_OFFSET + 4;
        b[BTN_DATA_OFFSET + 2..BTN_DATA_OFFSET + 4].copy_from_slice(&16u16.to_le_bytes());
        b[key_area..key_area + 8].copy_from_slice(&node_oid.to_le_bytes());
        b[key_area + 8..key_area + 16].copy_from_slice(&1u64.to_le_bytes());
        let value_end = BLK - BTREE_INFO_SIZE;
        b[value_end - 16 + 8..value_end - 16 + 16].copy_from_slice(&node_paddr.to_le_bytes());
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes());
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes());
        b
    }

    fn catalog_leaf(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0003u16.to_le_bytes());
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(records.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(records.len() * 8)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        let key_area = BTN_DATA_OFFSET + records.len() * 8;
        let value_end = BLK - BTREE_INFO_SIZE;
        let (mut kc, mut vc) = (0usize, 0usize);
        for (i, (key, value)) in records.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 8;
            b[toc..toc + 2].copy_from_slice(
                &u16::try_from(kc)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 2..toc + 4].copy_from_slice(
                &u16::try_from(key.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            vc += value.len();
            b[toc + 4..toc + 6].copy_from_slice(
                &u16::try_from(vc)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 6..toc + 8].copy_from_slice(
                &u16::try_from(value.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[key_area + kc..key_area + kc + key.len()].copy_from_slice(key);
            b[value_end - vc..value_end - vc + value.len()].copy_from_slice(value);
            kc += key.len();
        }
        b
    }

    fn extent_key(obj_id: u64, logical: u64) -> Vec<u8> {
        let mut k = ((u64::from(JObjType::FileExtent.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        k.extend_from_slice(&logical.to_le_bytes());
        k
    }

    fn extent_value(length: u64, phys_block: u64) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[0..8].copy_from_slice(&length.to_le_bytes());
        v[8..16].copy_from_slice(&phys_block.to_le_bytes());
        v
    }

    /// A volume with inode 5 spanning two 4 KiB extents at blocks 3 and 4.
    fn two_extent_file() -> (Catalog, Cursor<Vec<u8>>) {
        let leaf = catalog_leaf(&[
            (extent_key(5, 0), extent_value(4096, 3)),
            (extent_key(5, 4096), extent_value(4096, 4)),
        ]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(60, 2)); // catalog root virtual oid 60 -> block 2
        image.extend(leaf); // block 2
        let mut block3 = vec![0xC3u8; BLK]; // block 3 content
        let mut block4 = vec![0xC4u8; BLK]; // block 4 content
        block3[0] = 0x01;
        block4[0] = 0x02;
        image.append(&mut block3);
        image.append(&mut block4);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(60),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn reads_a_multi_extent_file() {
        let (catalog, mut reader) = two_extent_file();
        let file = File::open(&catalog, &mut reader, 5, 8192).unwrap();
        assert_eq!(file.extents().len(), 2);

        let content = file
            .read_all(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
            )
            .unwrap();
        assert_eq!(content.len(), 8192);
        assert_eq!(content[0], 0x01); // first byte of block 3
        assert_eq!(content[1], 0xC3);
        assert_eq!(content[4096], 0x02); // first byte of block 4
    }

    #[test]
    fn reads_across_an_extent_boundary() {
        let (catalog, mut reader) = two_extent_file();
        let file = File::open(&catalog, &mut reader, 5, 8192).unwrap();
        let mut buf = [0u8; 4];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                4094,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, 4);
        // Two bytes from block 3's tail, then two from block 4's head.
        assert_eq!(buf, [0xC3, 0xC3, 0x02, 0xC4]);
    }

    #[test]
    fn reads_past_end_of_file_return_zero() {
        let (catalog, mut reader) = two_extent_file();
        let file = File::open(&catalog, &mut reader, 5, 8192).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(
            file.read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                8192,
                &mut buf
            )
            .unwrap(),
            0
        );
        // A read straddling EOF is truncated.
        assert_eq!(
            file.read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                8190,
                &mut buf
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn a_hole_with_no_extent_reads_as_zeros() {
        // Inode 5 has only the first extent but a logical size of 8192.
        let leaf = catalog_leaf(&[(extent_key(5, 0), extent_value(4096, 3))]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(60, 2));
        image.extend(leaf);
        image.append(&mut vec![0xC3u8; BLK]); // block 3
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(60),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let mut reader = Cursor::new(image);

        let file = File::open(&catalog, &mut reader, 5, 8192).unwrap();
        let content = file
            .read_all(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
            )
            .unwrap();
        assert_eq!(content.len(), 8192);
        assert!(content[..4096].iter().all(|&b| b == 0xC3));
        assert!(content[4096..].iter().all(|&b| b == 0)); // the hole
    }

    #[test]
    fn file_extent_key_size_is_sixteen_bytes() {
        // j_key_t header (8) + logical_addr u64 (8) = 16. A wrong constant
        // would label `Truncated` errors with a misleading expected length.
        assert_eq!(J_FILE_EXTENT_KEY_SIZE, J_KEY_SIZE + 8);
        assert_eq!(J_FILE_EXTENT_KEY_SIZE, 16);
    }

    #[test]
    fn file_size_returns_the_logical_size_it_was_built_with() {
        // The getter must report the size passed in, not a placeholder.
        assert_eq!(File::from_extents(8192, Vec::new()).size(), 8192);
        assert_eq!(File::from_extents(2, Vec::new()).size(), 2);
        assert_eq!(File::from_extents(0, Vec::new()).size(), 0);
    }

    #[test]
    fn read_at_caps_at_logical_size_when_the_extent_is_larger() {
        // Logical file size 10 with a backing extent that covers a whole
        // block: read at offset 4 must return exactly 6 bytes (size - offset),
        // never size + offset.
        let mut image = vec![0u8; 4 * BLK];
        image[3 * BLK..4 * BLK].fill(0xAA);
        let mut reader = Cursor::new(image);
        let file = File::from_extents(
            10,
            vec![FileExtent {
                logical_addr: 0,
                length: BLK as u64,
                phys_block_num: 3,
                crypto_id: 0,
            }],
        );
        let mut buf = [0u8; 64];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                4,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, 6);
        assert!(buf[..6].iter().all(|&b| b == 0xAA));
        // Nothing past the logical size is touched.
        assert!(buf[6..].iter().all(|&b| b == 0));
    }

    // --- Reads spanning a hole between physically non-contiguous extents ---

    /// A 16 KiB file whose two extents are not physically adjacent on disk:
    /// extent A is logical 0..4 KiB at phys block 3; a 4 KiB logical hole
    /// follows; extent B is logical 8..16 KiB at phys blocks 6..8. Blocks 4
    /// and 5 sit between the extents in the image with a distinct fill
    /// (0xFF) so a mis-routed read appears as polluted bytes.
    fn noncontiguous_extents_image() -> (Cursor<Vec<u8>>, File) {
        let mut image = vec![0u8; 8 * BLK];
        image[3 * BLK..4 * BLK].fill(0xAA); // extent A
        image[4 * BLK..6 * BLK].fill(0xFF); // gap — never an extent
        image[6 * BLK..8 * BLK].fill(0xBB); // extent B
        let extents = vec![
            FileExtent {
                logical_addr: 0,
                length: BLK as u64,
                phys_block_num: 3,
                crypto_id: 0,
            },
            FileExtent {
                logical_addr: 2 * BLK as u64,
                length: 2 * BLK as u64,
                phys_block_num: 6,
                crypto_id: 0,
            },
        ];
        (
            Cursor::new(image),
            File::from_extents(4 * BLK as u64, extents),
        )
    }

    #[test]
    fn read_at_mid_extent_stops_at_the_extent_end_not_past_it() {
        // Reading from offset 2 of extent A with a buffer that runs into the
        // hole. `extent.length - within` must cap the first chunk at the
        // extent's tail (BLK - 2 bytes); `extent.length + within` would keep
        // reading into the unrelated 0xFF gap on disk.
        let (mut reader, file) = noncontiguous_extents_image();
        let mut buf = vec![0u8; BLK + 4];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                2,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, BLK + 4);
        // First BLK-2 bytes from extent A's tail.
        assert!(buf[..BLK - 2].iter().all(|&b| b == 0xAA), "extent A tail");
        // Then 6 bytes of hole zero-fill — never the 0xFF gap.
        assert!(buf[BLK - 2..].iter().all(|&b| b == 0), "hole zero-fill");
        assert!(!buf.contains(&0xFF));
    }

    #[test]
    fn read_at_in_a_hole_panics_when_the_chunk_cap_is_inverted() {
        // Reading from offset BLK-6 with a small buffer: the hole branch
        // must cap its chunk at `to_read - done`, not `to_read + done`, so
        // the zero-fill stays inside the caller's buffer.
        let (mut reader, file) = noncontiguous_extents_image();
        let mut buf = vec![0u8; 300];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                (BLK - 6) as u64,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, 300);
        assert!(buf[..6].iter().all(|&b| b == 0xAA));
        assert!(buf[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_at_into_a_leading_hole_caps_chunk_by_subtraction() {
        // File whose first extent is at logical 4 KiB; reading from offset 0
        // lands in the leading hole with done=0. A mutated `to_read / done`
        // or `next / pos` would divide by zero and panic.
        let mut image = vec![0u8; 4 * BLK];
        image[3 * BLK..4 * BLK].fill(0xCC);
        let mut reader = Cursor::new(image);
        let file = File::from_extents(
            8 * BLK as u64,
            vec![FileExtent {
                logical_addr: 4 * BLK as u64,
                length: BLK as u64,
                phys_block_num: 3,
                crypto_id: 0,
            }],
        );
        let mut buf = vec![0u8; 100];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                0,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, 100);
        assert!(buf.iter().all(|&b| b == 0), "leading hole zero-fill");
    }

    #[test]
    fn read_at_traverses_a_hole_then_resumes_at_the_next_extent() {
        // Reading across the hole with a large buffer: the hole branch must
        // end at extent B's start (8 KiB), then extent B's content (0xBB)
        // must follow. A wrong `start > pos` filter or inflated `next - pos`
        // would silently zero-fill past extent B.
        let (mut reader, file) = noncontiguous_extents_image();
        let mut buf = vec![0u8; 5000];
        let n = file
            .read_at(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                (BLK - 6) as u64,
                &mut buf,
            )
            .unwrap();
        assert_eq!(n, 5000);
        assert!(buf[..6].iter().all(|&b| b == 0xAA), "extent A tail");
        assert!(buf[6..6 + BLK].iter().all(|&b| b == 0), "hole");
        assert!(
            buf[6 + BLK..].iter().all(|&b| b == 0xBB),
            "extent B must follow the hole"
        );
    }
}
