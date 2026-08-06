//! The common object header (`obj_phys_t`) shared by every APFS
//! container-layer object.
//!
//! Apple File System Reference, `02-objects.md`: every container object begins
//! with a 32-byte header carrying its Fletcher-64 checksum, identifiers, and
//! type information.

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, U32, U64, Unaligned};

use crate::error::{ApfsError, Result};

/// Mask selecting the object type from the low 16 bits of `o_type`.
pub const OBJECT_TYPE_MASK: u32 = 0x0000_FFFF;
/// Mask selecting the flag bits from the high 16 bits of `o_type`.
pub const OBJECT_TYPE_FLAGS_MASK: u32 = 0xFFFF_0000;
/// Mask selecting the storage-class bits of `o_type`.
pub const OBJ_STORAGETYPE_MASK: u32 = 0xC000_0000;
/// Mask of all `o_type` bits for which flags are currently defined.
pub const OBJECT_TYPE_FLAGS_DEFINED_MASK: u32 = 0xF800_0000;

/// Storage-class flag: the object is virtual (located via an object map).
pub const OBJ_VIRTUAL: u32 = 0x0000_0000;
/// Storage-class flag: the object is ephemeral (lives in a checkpoint).
pub const OBJ_EPHEMERAL: u32 = 0x8000_0000;
/// Storage-class flag: the object is physical (at a fixed block address).
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;
/// Flag: the object is stored without an `obj_phys_t` header.
pub const OBJ_NOHEADER: u32 = 0x2000_0000;
/// Flag: the object is encrypted.
pub const OBJ_ENCRYPTED: u32 = 0x1000_0000;
/// Flag: the object is not persisted across unmounts.
pub const OBJ_NONPERSISTENT: u32 = 0x0800_0000;

/// The on-disk `obj_phys_t` header — 32 bytes, little-endian.
///
/// Apple File System Reference, `02-objects.md`.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawObjPhys {
    /// 0x00: Fletcher-64 checksum of the object.
    pub o_cksum: [u8; 8],
    /// 0x08: the object's identifier.
    pub o_oid: U64<LE>,
    /// 0x10: identifier of the most recent transaction that modified it.
    pub o_xid: U64<LE>,
    /// 0x18: object type (low 16 bits) and flags (high 16 bits).
    pub o_type: U32<LE>,
    /// 0x1C: object subtype.
    pub o_subtype: U32<LE>,
}

/// Size of the `obj_phys_t` header in bytes (`MAX_CKSUM_SIZE` included).
pub const OBJ_PHYS_SIZE: usize = core::mem::size_of::<RawObjPhys>();

/// How an object is located on disk, encoded in the `o_type` flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// Located through an object map, keyed by (object id, transaction id).
    Virtual,
    /// Held in memory and persisted in checkpoints.
    Ephemeral,
    /// Stored at a fixed physical block address.
    Physical,
    /// The storage-class bits held a value APFS does not define.
    Unknown,
}

/// A parsed APFS common object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjPhys {
    /// The stored Fletcher-64 checksum of the object block.
    pub checksum: u64,
    /// The object's identifier.
    pub oid: u64,
    /// The transaction identifier of the object's most recent modification.
    pub xid: u64,
    /// The object's subtype (for B-tree nodes, the kind of records held).
    pub subtype: u32,
    /// The raw `o_type` field — type in the low 16 bits, flags in the high.
    raw_type: u32,
}

impl ObjPhys {
    /// Parses an object header from the start of `bytes`.
    ///
    /// `bytes` is typically a whole object block; only the leading
    /// [`OBJ_PHYS_SIZE`] bytes are consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] when fewer than [`OBJ_PHYS_SIZE`]
    /// bytes are available.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (raw, _rest) =
            RawObjPhys::ref_from_prefix(bytes).map_err(|_| ApfsError::Truncated {
                structure: "obj_phys_t",
                expected: OBJ_PHYS_SIZE,
                actual: bytes.len(),
            })?;
        Ok(Self {
            checksum: u64::from_le_bytes(raw.o_cksum),
            oid: raw.o_oid.get(),
            xid: raw.o_xid.get(),
            subtype: raw.o_subtype.get(),
            raw_type: raw.o_type.get(),
        })
    }

    /// The object type — the low 16 bits of `o_type`.
    #[must_use]
    pub fn object_type(&self) -> u16 {
        (self.raw_type & OBJECT_TYPE_MASK) as u16
    }

    /// The object type flags — the high 16 bits of `o_type`.
    #[must_use]
    pub fn type_flags(&self) -> u16 {
        ((self.raw_type & OBJECT_TYPE_FLAGS_MASK) >> 16) as u16
    }

    /// The raw, undecoded `o_type` field.
    #[must_use]
    pub fn raw_type(&self) -> u32 {
        self.raw_type
    }

    /// The decoded object type.
    #[must_use]
    pub fn object_kind(&self) -> crate::types::ObjectType {
        crate::types::ObjectType::from_type_field(self.raw_type)
    }

    /// The decoded object subtype — for a B-tree node, the kind of records
    /// it holds.
    #[must_use]
    pub fn subtype_kind(&self) -> crate::types::ObjectType {
        crate::types::ObjectType::from_type_field(self.subtype)
    }

    /// How the object is stored on disk.
    #[must_use]
    pub fn storage_class(&self) -> StorageClass {
        match self.raw_type & OBJ_STORAGETYPE_MASK {
            OBJ_VIRTUAL => StorageClass::Virtual,
            OBJ_EPHEMERAL => StorageClass::Ephemeral,
            OBJ_PHYSICAL => StorageClass::Physical,
            _ => StorageClass::Unknown,
        }
    }

    /// Whether the object is encrypted (`OBJ_ENCRYPTED`).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.raw_type & OBJ_ENCRYPTED != 0
    }

    /// Whether the object is stored without an `obj_phys_t` header
    /// (`OBJ_NOHEADER`).
    #[must_use]
    pub fn is_headerless(&self) -> bool {
        self.raw_type & OBJ_NOHEADER != 0
    }

    /// Whether the object is non-persistent (`OBJ_NONPERSISTENT`).
    #[must_use]
    pub fn is_nonpersistent(&self) -> bool {
        self.raw_type & OBJ_NONPERSISTENT != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 32-byte `obj_phys_t` with the given identifiers and type.
    fn header(oid: u64, xid: u64, o_type: u32, subtype: u32) -> [u8; OBJ_PHYS_SIZE] {
        let mut buf = [0u8; OBJ_PHYS_SIZE];
        buf[0x08..0x10].copy_from_slice(&oid.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&xid.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&o_type.to_le_bytes());
        buf[0x1C..0x20].copy_from_slice(&subtype.to_le_bytes());
        buf
    }

    #[test]
    fn obj_phys_size_is_32() {
        assert_eq!(OBJ_PHYS_SIZE, 32);
    }

    #[test]
    fn parses_identifiers_type_and_subtype() {
        let buf = header(0x1122_3344_5566_7788, 0x42, 0x4000_0001, 0x0000_000B);
        let obj = ObjPhys::parse(&buf).unwrap();
        assert_eq!(obj.oid, 0x1122_3344_5566_7788);
        assert_eq!(obj.xid, 0x42);
        assert_eq!(obj.object_type(), 0x0001);
        assert_eq!(obj.type_flags(), 0x4000);
        assert_eq!(obj.subtype, 0x0000_000B);
    }

    #[test]
    fn parses_a_prefix_of_a_larger_block() {
        let mut block = [0u8; 256];
        block[..OBJ_PHYS_SIZE].copy_from_slice(&header(7, 9, OBJ_PHYSICAL, 0));
        let obj = ObjPhys::parse(&block).unwrap();
        assert_eq!(obj.oid, 7);
        assert_eq!(obj.xid, 9);
    }

    #[test]
    fn truncated_input_is_rejected() {
        let short = [0u8; OBJ_PHYS_SIZE - 1];
        match ObjPhys::parse(&short) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "obj_phys_t");
                assert_eq!(expected, OBJ_PHYS_SIZE);
                assert_eq!(actual, OBJ_PHYS_SIZE - 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn storage_class_decodes_each_variant() {
        let virt = ObjPhys::parse(&header(1, 1, OBJ_VIRTUAL, 0)).unwrap();
        assert_eq!(virt.storage_class(), StorageClass::Virtual);

        let ephem = ObjPhys::parse(&header(1, 1, OBJ_EPHEMERAL, 0)).unwrap();
        assert_eq!(ephem.storage_class(), StorageClass::Ephemeral);

        let phys = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL, 0)).unwrap();
        assert_eq!(phys.storage_class(), StorageClass::Physical);

        // Both storage-class bits set is not a value APFS defines.
        let unknown = ObjPhys::parse(&header(1, 1, OBJ_STORAGETYPE_MASK, 0)).unwrap();
        assert_eq!(unknown.storage_class(), StorageClass::Unknown);
    }

    #[test]
    fn type_flag_predicates() {
        let encrypted = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL | OBJ_ENCRYPTED, 0)).unwrap();
        assert!(encrypted.is_encrypted());
        assert!(!encrypted.is_headerless());

        let plain = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL, 0)).unwrap();
        assert!(!plain.is_encrypted());
        assert!(!plain.is_nonpersistent());
    }

    #[test]
    fn object_and_subtype_kind_decode() {
        use crate::types::ObjectType;
        // A B-tree node holding file-system records: type BTREE_NODE,
        // subtype FSTREE, with the physical storage-class flag set.
        let buf = header(5, 7, OBJ_PHYSICAL | 0x03, 0x0E);
        let obj = ObjPhys::parse(&buf).unwrap();
        assert_eq!(obj.object_kind(), ObjectType::BtreeNode);
        assert_eq!(obj.subtype_kind(), ObjectType::FsTree);
    }

    #[test]
    fn checksum_field_round_trips() {
        let mut block = header(1, 1, OBJ_PHYSICAL, 0);
        let csum = crate::checksum::fletcher64(&block[crate::checksum::MAX_CKSUM_SIZE..]);
        block[..crate::checksum::MAX_CKSUM_SIZE].copy_from_slice(&csum.to_le_bytes());
        let obj = ObjPhys::parse(&block).unwrap();
        assert_eq!(obj.checksum, csum);
        assert!(crate::checksum::verify_block(&block));
    }

    #[test]
    fn object_type_returns_the_low_sixteen_bits_of_o_type() {
        // A getter mutated to `1` would happen to match `object_type() == 1`;
        // assert a value beyond 1 so the mutant cannot pass.
        let obj = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL | 0x000C, 0)).unwrap();
        assert_eq!(obj.object_type(), 0x000C);
    }

    #[test]
    fn raw_type_returns_the_full_o_type_field() {
        // `raw_type` exposes both the type nibble and the flag bits as one
        // u32; assertion must use a value that is neither 0 nor 1 so the
        // body mutants `with 0` and `with 1` both fail.
        let combined = OBJ_PHYSICAL | OBJ_ENCRYPTED | 0x0042;
        let obj = ObjPhys::parse(&header(1, 1, combined, 0)).unwrap();
        assert_eq!(obj.raw_type(), combined);
        // Sanity-check the combined value is well clear of `0` and `1`.
        assert!(obj.raw_type() > 1);
    }

    #[test]
    fn is_headerless_is_true_when_obj_noheader_is_set() {
        // Both sides of the predicate are needed so the body mutants
        // `with true` and `with false` are each killed by a wrong-direction
        // assertion.
        let headered = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL, 0)).unwrap();
        assert!(!headered.is_headerless());
        let headerless = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL | OBJ_NOHEADER, 0)).unwrap();
        assert!(headerless.is_headerless());
    }

    #[test]
    fn is_nonpersistent_is_true_when_obj_nonpersistent_is_set() {
        let persistent = ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL, 0)).unwrap();
        assert!(!persistent.is_nonpersistent());
        let nonpersistent =
            ObjPhys::parse(&header(1, 1, OBJ_PHYSICAL | OBJ_NONPERSISTENT, 0)).unwrap();
        assert!(nonpersistent.is_nonpersistent());
    }
}
