//! EFI jumpstart and APFS partition detection.
//!
//! A bootable APFS container carries an EFI jumpstart record
//! (`nx_efi_jumpstart_t`) locating the EFI driver embedded in the container.
//! An APFS container on a GPT disk is identified by a fixed partition-type
//! GUID.
//!
//! Apple File System Reference, `03-efi-jumpstart.md`.

use alloc::vec::Vec;

use crate::container::{NX_MAGIC, NX_MINIMUM_BLOCK_SIZE};
use crate::error::{ApfsError, Result};
use crate::io::{ErrorKind, Read, Seek, SeekFrom};
use crate::object::{OBJ_PHYS_SIZE, ObjPhys};
use crate::types::{ObjectType, PRANGE_SIZE, Prange};

/// EFI jumpstart magic (`NX_EFI_JUMPSTART_MAGIC` `'RDSJ'`) as the
/// little-endian `u32` it forms on disk — the bytes `JSDR`.
pub const NX_EFI_JUMPSTART_MAGIC: u32 = u32::from_le_bytes(*b"JSDR");
/// The only supported EFI jumpstart version (`NX_EFI_JUMPSTART_VERSION`).
pub const NX_EFI_JUMPSTART_VERSION: u32 = 1;

/// GPT partition-type GUID of an APFS container (`APFS_GPT_PARTITION_UUID`),
/// in its canonical string form.
pub const APFS_GPT_PARTITION_UUID: &str = "7C3457EF-0000-11AA-AA11-00306543ECAC";

/// GPT partition-type GUID of an APFS container, in the mixed-endian 16-byte
/// form GPT stores on disk.
pub const APFS_GPT_PARTITION_TYPE: [u8; 16] = [
    0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
];

/// Offset of the `nej_rec_extents` array within `nx_efi_jumpstart_t`.
///
/// `obj_phys_t` (32) + four `u32` fields (16) + `nej_reserved[16]` (128).
const NEJ_EXTENTS_OFFSET: usize = OBJ_PHYS_SIZE + 16 + 128;

/// Returns whether the reader holds an APFS container.
///
/// Reads the block-zero container superblock and checks its magic. A full
/// validation is left to [`NxSuperblock::parse`](crate::container::NxSuperblock::parse).
///
/// # Errors
///
/// Propagates I/O errors.
///
/// # Panics
///
/// Panics only if the fixed superblock-magic offsets cease to fit the
/// compile-time-sized probe buffer.
pub fn is_apfs_container<T: Read + Seek>(reader: &mut T) -> Result<bool> {
    reader.seek(SeekFrom::Start(0))?;
    let mut probe = [0u8; NX_MINIMUM_BLOCK_SIZE as usize];
    if let Err(error) = reader.read_exact(&mut probe) {
        // An image too small to hold a superblock is simply not APFS; any
        // other read failure is a real I/O fault and must be propagated.
        if error.kind() == ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(error.into());
    }
    // `nx_magic` is at offset 0x20 of the container superblock.
    let magic = u32::from_le_bytes(probe[0x20..0x24].try_into().expect("4 bytes"));
    Ok(magic == NX_MAGIC)
}

/// A parsed EFI jumpstart record (`nx_efi_jumpstart_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiJumpstart {
    /// Length, in bytes, of the embedded EFI driver.
    pub efi_file_len: u32,
    /// Physical extents holding the EFI driver.
    pub extents: Vec<Prange>,
}

impl EfiJumpstart {
    /// Parses an EFI jumpstart record from its block.
    ///
    /// The block is located by the `nx_efi_jumpstart` field of the container
    /// superblock.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block,
    /// [`ApfsError::InvalidMagic`] for a bad `nej_magic`, or
    /// [`ApfsError::Unsupported`] for an unrecognized version.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed-width EFI fields cease to match the minimum
    /// block length checked before parsing.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < NEJ_EXTENTS_OFFSET {
            return Err(ApfsError::Truncated {
                structure: "nx_efi_jumpstart_t",
                expected: NEJ_EXTENTS_OFFSET,
                actual: block.len(),
            });
        }
        let header = ObjPhys::parse(block)?;
        if header.object_kind() != ObjectType::EfiJumpstart {
            return Err(ApfsError::Malformed {
                structure: "nx_efi_jumpstart_t",
                reason: "object type is not an EFI jumpstart record",
            });
        }
        let magic = u32::from_le_bytes(block[0x20..0x24].try_into().expect("4 bytes"));
        if magic != NX_EFI_JUMPSTART_MAGIC {
            return Err(ApfsError::InvalidMagic {
                structure: "nx_efi_jumpstart_t",
                expected: NX_EFI_JUMPSTART_MAGIC,
                actual: magic,
            });
        }
        let version = u32::from_le_bytes(block[0x24..0x28].try_into().expect("4 bytes"));
        if version != NX_EFI_JUMPSTART_VERSION {
            return Err(ApfsError::Unsupported("unrecognized EFI jumpstart version"));
        }
        let efi_file_len = u32::from_le_bytes(block[0x28..0x2C].try_into().expect("4 bytes"));
        let num_extents =
            u32::from_le_bytes(block[0x2C..0x30].try_into().expect("4 bytes")) as usize;

        // Validate the extent array fits the block before trusting the
        // on-disk count to size an allocation.
        num_extents
            .checked_mul(PRANGE_SIZE)
            .and_then(|len| NEJ_EXTENTS_OFFSET.checked_add(len))
            .filter(|&end| end <= block.len())
            .ok_or(ApfsError::Malformed {
                structure: "nx_efi_jumpstart_t",
                reason: "extent array extends past the block",
            })?;

        let mut extents = Vec::with_capacity(num_extents);
        for i in 0..num_extents {
            let start = NEJ_EXTENTS_OFFSET + i * PRANGE_SIZE;
            let slice = block
                .get(start..start + PRANGE_SIZE)
                .ok_or(ApfsError::Malformed {
                    structure: "nx_efi_jumpstart_t",
                    reason: "extent array extends past the block",
                })?;
            extents.push(Prange::parse(slice)?);
        }
        Ok(Self {
            efi_file_len,
            extents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::OBJ_PHYSICAL;
    use crate::types::Paddr;
    use std::io::Cursor;

    const BLK: usize = 4096;

    /// Builds an EFI jumpstart block with `num_extents` extents.
    fn jumpstart(magic: u32, version: u32, extents: &[(i64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        // o_type: OBJECT_TYPE_EFI_JUMPSTART (0x14).
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x14).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&magic.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&version.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&4096u32.to_le_bytes()); // nej_efi_file_len
        b[0x2C..0x30].copy_from_slice(
            &u32::try_from(extents.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        for (i, &(start, count)) in extents.iter().enumerate() {
            let off = NEJ_EXTENTS_OFFSET + i * PRANGE_SIZE;
            b[off..off + 8].copy_from_slice(&start.to_le_bytes());
            b[off + 8..off + 16].copy_from_slice(&count.to_le_bytes());
        }
        b
    }

    #[test]
    fn detects_an_apfs_container() {
        let mut block = vec![0u8; BLK];
        block[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        let mut reader = Cursor::new(block);
        assert!(is_apfs_container(&mut reader).unwrap());
    }

    #[test]
    fn rejects_a_non_apfs_image() {
        let mut reader = Cursor::new(vec![0u8; BLK]);
        assert!(!is_apfs_container(&mut reader).unwrap());
        // An image too small for a superblock is simply not APFS.
        let mut tiny = Cursor::new(vec![0u8; 16]);
        assert!(!is_apfs_container(&mut tiny).unwrap());
    }

    #[test]
    fn parses_an_efi_jumpstart_record() {
        let block = jumpstart(NX_EFI_JUMPSTART_MAGIC, 1, &[(64, 2), (200, 1)]);
        let js = EfiJumpstart::parse(&block).unwrap();
        assert_eq!(js.efi_file_len, 4096);
        assert_eq!(js.extents.len(), 2);
        assert_eq!(js.extents[0].start, Paddr(64));
        assert_eq!(js.extents[1].block_count, 1);
    }

    #[test]
    fn rejects_a_bad_magic() {
        let block = jumpstart(0xDEAD_BEEF, 1, &[]);
        assert!(matches!(
            EfiJumpstart::parse(&block),
            Err(ApfsError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn rejects_an_unknown_version() {
        let block = jumpstart(NX_EFI_JUMPSTART_MAGIC, 99, &[]);
        assert!(matches!(
            EfiJumpstart::parse(&block),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_an_oversized_extent_count() {
        // A crafted nej_num_extents must be rejected before allocation.
        let mut block = jumpstart(NX_EFI_JUMPSTART_MAGIC, 1, &[]);
        block[0x2C..0x30].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            EfiJumpstart::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn partition_type_guid_round_trips() {
        // The mixed-endian bytes correspond to the canonical UUID string.
        assert_eq!(
            APFS_GPT_PARTITION_UUID,
            "7C3457EF-0000-11AA-AA11-00306543ECAC"
        );
        assert_eq!(APFS_GPT_PARTITION_TYPE[0], 0xEF);
        assert_eq!(APFS_GPT_PARTITION_TYPE[15], 0xAC);
    }

    #[test]
    fn nej_extents_offset_pins_the_extent_array_position() {
        // The constant must equal obj_phys_t (32) + four u32 fields (16) +
        // 128 bytes of `nej_reserved`. Any arithmetic mutation that changes
        // it (e.g. `+ → *` or `+ → -`) shifts the extent array to the wrong
        // offset, so a single assertion pins all three L37 mutations.
        assert_eq!(NEJ_EXTENTS_OFFSET, OBJ_PHYS_SIZE + 16 + 128);
        assert_eq!(NEJ_EXTENTS_OFFSET, 176);
    }

    #[test]
    fn parse_accepts_a_block_just_large_enough_for_the_fixed_header() {
        // A block exactly NEJ_EXTENTS_OFFSET bytes long has zero extents but
        // every fixed field set. The truncation check is `len < EXTENTS_OFF`,
        // so `<=` would reject this size and `==` would only flag exact
        // matches — both must accept a 176-byte buffer with zero extents.
        let mut b = vec![0u8; NEJ_EXTENTS_OFFSET];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x14).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&NX_EFI_JUMPSTART_MAGIC.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&NX_EFI_JUMPSTART_VERSION.to_le_bytes());
        let js = EfiJumpstart::parse(&b).unwrap();
        assert_eq!(js.extents.len(), 0);
    }

    #[test]
    fn parse_rejects_a_block_one_byte_short_of_the_header() {
        // A 175-byte buffer is one byte short of NEJ_EXTENTS_OFFSET and must
        // surface a Truncated error; mutating `<` to `==` would only catch
        // an exactly-176-byte buffer and let this shorter one through.
        let b = vec![0u8; NEJ_EXTENTS_OFFSET - 1];
        match EfiJumpstart::parse(&b) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "nx_efi_jumpstart_t");
                assert_eq!(expected, NEJ_EXTENTS_OFFSET);
                assert_eq!(actual, NEJ_EXTENTS_OFFSET - 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_an_extent_slice_that_runs_past_a_tight_block() {
        // A 192-byte block fits exactly one extent at offset 176..192. The
        // per-iteration slice is `start..start + PRANGE_SIZE`; mutating
        // `+` to `*` makes it `start..start * PRANGE_SIZE = 176..2816`,
        // far past the buffer, so the get returns None and parse fails.
        let mut b = vec![0u8; NEJ_EXTENTS_OFFSET + PRANGE_SIZE];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x14).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&NX_EFI_JUMPSTART_MAGIC.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&NX_EFI_JUMPSTART_VERSION.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&1024u32.to_le_bytes()); // nej_efi_file_len
        b[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // nej_num_extents
        // The one extent's prange bytes live at the very end of the buffer.
        b[NEJ_EXTENTS_OFFSET..NEJ_EXTENTS_OFFSET + 8].copy_from_slice(&42i64.to_le_bytes());
        b[NEJ_EXTENTS_OFFSET + 8..NEJ_EXTENTS_OFFSET + 16].copy_from_slice(&3u64.to_le_bytes());

        let js = EfiJumpstart::parse(&b).unwrap();
        assert_eq!(js.extents.len(), 1);
        assert_eq!(js.extents[0].start, Paddr(42));
        assert_eq!(js.extents[0].block_count, 3);
    }
}
