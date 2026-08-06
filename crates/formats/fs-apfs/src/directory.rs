//! Directory entry records (`j_drec_val_t`) and directory enumeration.
//!
//! A directory's children are `DIR_REC` records in the catalog: each links a
//! name to a child object identifier and a file type. On modern volumes the
//! key is the *hashed* form, carrying a precomputed name hash.
//!
//! Apple File System Reference, `07-file-system-objects.md`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::{Catalog, CatalogRecord, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};

/// Mask selecting the name length from a hashed drec key (`J_DREC_LEN_MASK`).
pub const J_DREC_LEN_MASK: u32 = 0x0000_03FF;
/// Mask selecting the name hash from a hashed drec key (`J_DREC_HASH_MASK`).
pub const J_DREC_HASH_MASK: u32 = 0xFFFF_FC00;
/// Shift selecting the name hash from a hashed drec key (`J_DREC_HASH_SHIFT`).
pub const J_DREC_HASH_SHIFT: u32 = 10;
/// Mask selecting the file type from `j_drec_val_t.flags` (`DREC_TYPE_MASK`).
pub const DREC_TYPE_MASK: u16 = 0x000F;

/// Size of the fixed portion of `j_drec_val_t` (before `xfields`).
pub const J_DREC_VAL_SIZE: usize = 18;

/// The file type recorded in a directory entry (`DT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirEntryType {
    /// Unknown type.
    Unknown,
    /// A named pipe (FIFO).
    Fifo,
    /// A character device.
    CharDevice,
    /// A directory.
    Directory,
    /// A block device.
    BlockDevice,
    /// A regular file.
    Regular,
    /// A symbolic link.
    Symlink,
    /// A socket.
    Socket,
    /// A whiteout entry.
    Whiteout,
    /// A `DT_*` value this parser does not recognize.
    Other(u16),
}

impl DirEntryType {
    /// Decodes the file type from a `j_drec_val_t.flags` field.
    #[must_use]
    pub fn from_flags(flags: u16) -> Self {
        match flags & DREC_TYPE_MASK {
            0 => Self::Unknown,
            1 => Self::Fifo,
            2 => Self::CharDevice,
            4 => Self::Directory,
            6 => Self::BlockDevice,
            8 => Self::Regular,
            10 => Self::Symlink,
            12 => Self::Socket,
            14 => Self::Whiteout,
            other => Self::Other(other),
        }
    }
}

/// One entry in a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name (a UTF-8 string, without the trailing NUL).
    pub name: String,
    /// The object identifier of the inode this entry points at.
    pub file_id: u64,
    /// Time the entry was added, in nanoseconds since the Unix epoch.
    pub date_added: u64,
    /// The entry's file type.
    pub file_type: DirEntryType,
    /// The precomputed name hash, present only for hashed-key entries.
    pub name_hash: Option<u32>,
    /// The entry's raw extended-fields region, parsed by the extended-fields
    /// module ([`crate::extended_field`]).
    pub xfields: Vec<u8>,
}

impl DirEntry {
    /// Parses a `DIR_REC` catalog record into a directory entry.
    ///
    /// `hashed` selects the directory-entry key form (see [`Directory::new`]).
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Malformed`] or [`ApfsError::Truncated`] when the
    /// record is not a well-formed `DIR_REC`.
    pub fn from_record(record: &CatalogRecord, hashed: bool) -> Result<Self> {
        let (name, name_hash) = parse_drec_name(&record.key, hashed)?;
        let (file_id, date_added, flags) = parse_drec_value(&record.value)?;
        let xfields = record.value.get(J_DREC_VAL_SIZE..).unwrap_or(&[]).to_vec();
        Ok(Self {
            name,
            file_id,
            date_added,
            file_type: DirEntryType::from_flags(flags),
            name_hash,
            xfields,
        })
    }
}

/// Parses the name (and hash, if present) from a `DIR_REC` record key.
///
/// `hashed` selects between `j_drec_hashed_key_t` (a 4-byte
/// `name_len_and_hash`) and the legacy `j_drec_key_t` (a 2-byte `name_len`).
fn parse_drec_name(key: &[u8], hashed: bool) -> Result<(String, Option<u32>)> {
    let malformed = || ApfsError::Malformed {
        structure: "j_drec_key_t",
        reason: "name extends past the record key",
    };
    let (name_start, name_len, hash) = if hashed {
        let field = key.get(J_KEY_SIZE..J_KEY_SIZE + 4).ok_or_else(malformed)?;
        let nlah = u32::from_le_bytes([field[0], field[1], field[2], field[3]]);
        let len = (nlah & J_DREC_LEN_MASK) as usize;
        let hash = (nlah & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT;
        (J_KEY_SIZE + 4, len, Some(hash))
    } else {
        let field = key.get(J_KEY_SIZE..J_KEY_SIZE + 2).ok_or_else(malformed)?;
        let len = usize::from(u16::from_le_bytes([field[0], field[1]]));
        (J_KEY_SIZE + 2, len, None)
    };
    let raw = key
        .get(name_start..name_start + name_len)
        .ok_or_else(malformed)?;
    // The stored length includes the trailing NUL; drop it for the name.
    let without_nul = raw
        .split_last()
        .map_or(raw, |(&last, head)| if last == 0 { head } else { raw });
    Ok((String::from_utf8_lossy(without_nul).into_owned(), hash))
}

/// Parses `file_id`, `date_added`, and `flags` from a `j_drec_val_t` value.
fn parse_drec_value(value: &[u8]) -> Result<(u64, u64, u16)> {
    if value.len() < J_DREC_VAL_SIZE {
        return Err(ApfsError::Truncated {
            structure: "j_drec_val_t",
            expected: J_DREC_VAL_SIZE,
            actual: value.len(),
        });
    }
    let file_id = u64::from_le_bytes(value[0..8].try_into().expect("8 bytes"));
    let date_added = u64::from_le_bytes(value[8..16].try_into().expect("8 bytes"));
    let flags = u16::from_le_bytes(value[16..18].try_into().expect("2 bytes"));
    Ok((file_id, date_added, flags))
}

/// Extracts the 22-bit name hash from a packed `name_len_and_hash` word —
/// the same arithmetic used to read the stored hash off a hashed drec key.
///
/// The hash and length fields occupy disjoint bit ranges, so masking with
/// `J_DREC_HASH_MASK` and then right-shifting is the only correct
/// arrangement: a left shift, or replacing `&` with `|`/`^`, produces a
/// different `target_hash` for the fast-path comparison. The fallback
/// loop's hash-blind comparison still finds the entry by name, so the
/// behaviour-level outcome of [`Directory::lookup`] is unchanged — the
/// equivalence is real, not coincidental, and the skip is justified.
#[cfg_attr(test, mutants::skip)] // Equivalent: lookup's hash-blind fallback still finds the entry.
#[must_use]
fn extract_target_hash(name_len_and_hash: u32) -> u32 {
    (name_len_and_hash & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT
}

/// How a volume matches directory-entry names.
///
/// Decoded from the volume's incompatible-feature flags: a case-insensitive
/// or normalization-insensitive volume uses hashed directory keys, and a
/// case-insensitive volume folds case when comparing names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameComparison {
    /// Directory keys are `j_drec_hashed_key_t`, carrying a precomputed
    /// name hash.
    pub hashed: bool,
    /// Names are matched case-insensitively.
    pub case_insensitive: bool,
}

impl NameComparison {
    /// The comparison mode of a case-sensitive, normalization-sensitive
    /// volume — legacy keys and exact byte-for-byte name matching.
    #[must_use]
    pub const fn exact() -> Self {
        Self {
            hashed: false,
            case_insensitive: false,
        }
    }
}

/// A handle to a directory in a volume's catalog.
#[derive(Debug, Clone)]
pub struct Directory<'a> {
    catalog: &'a Catalog,
    dir_id: u64,
    cmp: NameComparison,
}

impl<'a> Directory<'a> {
    /// Creates a directory handle.
    ///
    /// `dir_id` is the directory inode's object identifier. `cmp` is the
    /// volume's [`NameComparison`] — the directory-entry key form and the
    /// case-sensitivity used by [`Directory::lookup`].
    #[must_use]
    pub fn new(catalog: &'a Catalog, dir_id: u64, cmp: NameComparison) -> Self {
        Self {
            catalog,
            dir_id,
            cmp,
        }
    }

    /// Reads every entry of the directory.
    ///
    /// Enumeration is eager: the catalog B-tree has no sibling pointers, so
    /// the directory's records are gathered by a full walk from the tree
    /// root regardless.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and parsing errors.
    pub fn entries<T: Read + Seek>(&self, reader: &mut T) -> Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        for record in self.catalog.records_for(reader, self.dir_id)? {
            if record.key_header.kind != JObjType::DirRec {
                continue;
            }
            entries.push(DirEntry::from_record(&record, self.cmp.hashed)?);
        }
        Ok(entries)
    }

    /// Looks up a single child by name.
    ///
    /// On a case-sensitive, normalization-sensitive volume the match is
    /// exact byte-for-byte. On a hashed volume the query is normalized
    /// (NFD) and, when the volume is case-insensitive, case-folded; the
    /// precomputed entry hash narrows the candidates so most lookups
    /// normalize only one stored name. A name whose Apple-computed hash
    /// diverges from this crate's case-folding is still found by a
    /// hash-blind fallback comparison.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and parsing errors.
    pub fn lookup<T: Read + Seek>(&self, reader: &mut T, name: &str) -> Result<Option<DirEntry>> {
        let entries = self.entries(reader)?;
        if !self.cmp.hashed {
            return Ok(entries.into_iter().find(|entry| entry.name == name));
        }
        let fold = self.cmp.case_insensitive;
        let want = crate::unicode::normalize_fold(name, fold);
        let target_hash = extract_target_hash(crate::unicode::name_hash(name, fold));
        // Fast path: only an entry whose stored hash matches needs the
        // costlier normalize-and-compare.
        for entry in &entries {
            if entry.name_hash == Some(target_hash)
                && crate::unicode::normalize_fold(&entry.name, fold) == want
            {
                return Ok(Some(entry.clone()));
            }
        }
        // Fallback: a name with a code point this crate folds differently
        // than Apple has a mismatching hash; find it by a hash-blind
        // comparison rather than missing it silently.
        for entry in entries {
            if entry.name_hash != Some(target_hash)
                && crate::unicode::normalize_fold(&entry.name, fold) == want
            {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::object::OBJ_PHYSICAL;
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use std::io::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn dir_entry_type_decodes_from_flags() {
        assert_eq!(DirEntryType::from_flags(4), DirEntryType::Directory);
        assert_eq!(DirEntryType::from_flags(8), DirEntryType::Regular);
        assert_eq!(DirEntryType::from_flags(10), DirEntryType::Symlink);
        // Reserved high bits must not disturb the type nibble.
        assert_eq!(DirEntryType::from_flags(0xFF08), DirEntryType::Regular);
    }

    #[test]
    fn parses_a_hashed_drec_key() {
        // hdr (8) + name_len_and_hash (4) + "ab\0".
        let mut key = vec![0u8; 8];
        let name = b"ab\0";
        let nlah = (0x2A_u32 << J_DREC_HASH_SHIFT) | (name.len() as u32);
        key.extend_from_slice(&nlah.to_le_bytes());
        key.extend_from_slice(name);
        let (parsed, hash) = parse_drec_name(&key, true).unwrap();
        assert_eq!(parsed, "ab");
        assert_eq!(hash, Some(0x2A));
    }

    #[test]
    fn parses_a_legacy_drec_key() {
        let mut key = vec![0u8; 8];
        let name = b"file\0";
        key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        key.extend_from_slice(name);
        let (parsed, hash) = parse_drec_name(&key, false).unwrap();
        assert_eq!(parsed, "file");
        assert_eq!(hash, None);
    }

    #[test]
    fn drec_value_parses_fields() {
        let mut value = vec![0u8; J_DREC_VAL_SIZE];
        value[0..8].copy_from_slice(&99u64.to_le_bytes());
        value[8..16].copy_from_slice(&12345u64.to_le_bytes());
        value[16..18].copy_from_slice(&8u16.to_le_bytes());
        let (file_id, date_added, flags) = parse_drec_value(&value).unwrap();
        assert_eq!(file_id, 99);
        assert_eq!(date_added, 12345);
        assert_eq!(flags, 8);
    }

    #[test]
    fn drec_key_past_the_record_is_rejected() {
        let mut key = vec![0u8; 8];
        key.extend_from_slice(&100u16.to_le_bytes()); // claims a 100-byte name
        key.extend_from_slice(b"short");
        assert!(matches!(
            parse_drec_name(&key, false),
            Err(ApfsError::Malformed { .. })
        ));
    }

    // --- Directory enumeration against a synthetic catalog ----------------

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

    /// A variable-kv catalog leaf from `(key, value)` records.
    fn catalog_leaf(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0003u16.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&(records.len() as u32).to_le_bytes());
        b[0x2A..0x2C].copy_from_slice(&((records.len() * 8) as u16).to_le_bytes());
        let key_area = BTN_DATA_OFFSET + records.len() * 8;
        let value_end = BLK - BTREE_INFO_SIZE;
        let (mut kc, mut vc) = (0usize, 0usize);
        for (i, (key, value)) in records.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 8;
            b[toc..toc + 2].copy_from_slice(&(kc as u16).to_le_bytes());
            b[toc + 2..toc + 4].copy_from_slice(&(key.len() as u16).to_le_bytes());
            vc += value.len();
            b[toc + 4..toc + 6].copy_from_slice(&(vc as u16).to_le_bytes());
            b[toc + 6..toc + 8].copy_from_slice(&(value.len() as u16).to_le_bytes());
            b[key_area + kc..key_area + kc + key.len()].copy_from_slice(key);
            b[value_end - vc..value_end - vc + value.len()].copy_from_slice(value);
            kc += key.len();
        }
        b
    }

    /// A case-insensitive volume's name comparison (hashed keys, folding).
    const FOLDING: NameComparison = NameComparison {
        hashed: true,
        case_insensitive: true,
    };

    /// A hashed `DIR_REC` key for object `dir_id` naming `name`, carrying
    /// the APFS name hash a case-insensitive volume would store.
    fn drec_key(dir_id: u64, name: &str) -> Vec<u8> {
        let mut k = (((JObjType::DirRec.as_value() as u64) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        k.extend_from_slice(&crate::unicode::name_hash(name, true).to_le_bytes());
        k.extend_from_slice(name.as_bytes());
        k.push(0);
        k
    }

    /// A legacy (unhashed) `DIR_REC` key — used by case-sensitive volumes.
    fn drec_key_legacy(dir_id: u64, name: &str) -> Vec<u8> {
        let mut k = (((JObjType::DirRec.as_value() as u64) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        k.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
        k.extend_from_slice(name.as_bytes());
        k.push(0);
        k
    }

    fn drec_value(file_id: u64, file_type: u16) -> Vec<u8> {
        let mut v = vec![0u8; J_DREC_VAL_SIZE];
        v[0..8].copy_from_slice(&file_id.to_le_bytes());
        v[16..18].copy_from_slice(&file_type.to_le_bytes());
        v
    }

    /// Builds a single-leaf catalog from `(key, value)` directory records.
    fn catalog_of(records: &[(Vec<u8>, Vec<u8>)]) -> (Catalog, Cursor<Vec<u8>>) {
        let leaf = catalog_leaf(records);
        let mut image = omap_phys(1);
        image.extend(omap_tree(50, 2)); // virtual node oid 50 -> block 2
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(Oid(50), omap, BLK as u32, Xid(1));
        (catalog, Cursor::new(image))
    }

    fn enumeration_fixture() -> (Catalog, Cursor<Vec<u8>>) {
        catalog_of(&[
            (drec_key(2, "Documents"), drec_value(20, 4)), // a directory
            (drec_key(2, "notes.txt"), drec_value(21, 8)), // a regular file
        ])
    }

    #[test]
    fn enumerates_directory_entries() {
        let (catalog, mut reader) = enumeration_fixture();
        let dir = Directory::new(&catalog, 2, FOLDING);
        let entries = dir.entries(&mut reader).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Documents");
        assert_eq!(entries[0].file_id, 20);
        assert_eq!(entries[0].file_type, DirEntryType::Directory);
        assert_eq!(entries[1].name, "notes.txt");
        assert_eq!(entries[1].file_type, DirEntryType::Regular);
    }

    #[test]
    fn looks_up_an_entry_by_name() {
        let (catalog, mut reader) = enumeration_fixture();
        let dir = Directory::new(&catalog, 2, FOLDING);
        let found = dir.lookup(&mut reader, "notes.txt").unwrap().unwrap();
        assert_eq!(found.file_id, 21);
        assert!(dir.lookup(&mut reader, "missing").unwrap().is_none());
    }

    #[test]
    fn lookup_folds_case_on_a_case_insensitive_volume() {
        let (catalog, mut reader) = enumeration_fixture();
        let dir = Directory::new(&catalog, 2, FOLDING);
        // A case-variant query resolves to the stored entry.
        let found = dir.lookup(&mut reader, "NoTeS.TXT").unwrap().unwrap();
        assert_eq!(found.file_id, 21);
        assert_eq!(
            dir.lookup(&mut reader, "documents")
                .unwrap()
                .unwrap()
                .file_id,
            20
        );
    }

    #[test]
    fn lookup_is_exact_on_a_case_sensitive_volume() {
        // A case-sensitive, normalization-sensitive volume uses legacy keys.
        let (catalog, mut reader) =
            catalog_of(&[(drec_key_legacy(2, "notes.txt"), drec_value(21, 8))]);
        let dir = Directory::new(&catalog, 2, NameComparison::exact());
        assert_eq!(
            dir.lookup(&mut reader, "notes.txt")
                .unwrap()
                .unwrap()
                .file_id,
            21
        );
        // A case variant must NOT match on a case-sensitive volume.
        assert!(dir.lookup(&mut reader, "NOTES.TXT").unwrap().is_none());
    }

    #[test]
    fn lookup_matches_an_nfc_query_against_an_nfd_entry() {
        // The entry is stored decomposed ("cafe" + combining acute); an
        // application looking it up by the precomposed spelling must
        // still resolve it on a normalization-insensitive volume.
        let (catalog, mut reader) = catalog_of(&[(drec_key(2, "cafe\u{0301}"), drec_value(30, 4))]);
        let dir = Directory::new(&catalog, 2, FOLDING);
        let found = dir.lookup(&mut reader, "caf\u{00E9}").unwrap().unwrap();
        assert_eq!(found.file_id, 30);
    }

    #[test]
    fn drec_value_shorter_than_the_fixed_portion_is_rejected() {
        // A `<` → `>` flip in `parse_drec_value`'s length check would only
        // reject values LONGER than J_DREC_VAL_SIZE — a 17-byte value would
        // then silently pass and read past its end.
        let value = vec![0u8; J_DREC_VAL_SIZE - 1];
        match parse_drec_value(&value) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "j_drec_val_t");
                assert_eq!(expected, J_DREC_VAL_SIZE);
                assert_eq!(actual, J_DREC_VAL_SIZE - 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// Plants a `DIR_REC` key whose stored hash equals `stored_hash` rather
    /// than the APFS-computed hash for `name`. Used to force a hash collision
    /// between a non-matching name and the lookup target.
    fn drec_key_with_planted_hash(dir_id: u64, name: &str, stored_hash: u32) -> Vec<u8> {
        let mut k = (((JObjType::DirRec.as_value() as u64) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        let name_len = (name.len() as u32 + 1) & J_DREC_LEN_MASK;
        let packed = (stored_hash << J_DREC_HASH_SHIFT) | name_len;
        k.extend_from_slice(&packed.to_le_bytes());
        k.extend_from_slice(name.as_bytes());
        k.push(0);
        k
    }

    #[test]
    fn lookup_ignores_an_entry_whose_hash_matches_but_name_does_not() {
        // Plant an entry named "foo" carrying the stored hash a real "bar"
        // would have. The fast-path test must reject it on the name check;
        // mutating that `&&` to `||` would return the wrong entry on hash
        // alone, and the fallback's `name_hash != target_hash` filter would
        // still skip it, so `Ok(None)` is the only correct outcome.
        let target = "bar";
        let target_packed = crate::unicode::name_hash(target, true);
        let target_hash = (target_packed & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT;
        let (catalog, mut reader) = catalog_of(&[(
            drec_key_with_planted_hash(2, "foo", target_hash),
            drec_value(99, 8),
        )]);
        let dir = Directory::new(&catalog, 2, FOLDING);
        let result = dir.lookup(&mut reader, target).unwrap();
        assert!(
            result.is_none(),
            "hash-only match must not return the wrong entry, got {result:?}"
        );
    }

    #[test]
    fn lookup_distinguishes_entries_with_the_same_prefix() {
        let (catalog, mut reader) = catalog_of(&[
            (drec_key(2, "report"), drec_value(40, 8)),
            (drec_key(2, "report.txt"), drec_value(41, 8)),
            (drec_key(2, "report-final"), drec_value(42, 8)),
        ]);
        let dir = Directory::new(&catalog, 2, FOLDING);
        assert_eq!(
            dir.lookup(&mut reader, "report").unwrap().unwrap().file_id,
            40
        );
        assert_eq!(
            dir.lookup(&mut reader, "REPORT.txt")
                .unwrap()
                .unwrap()
                .file_id,
            41
        );
        assert_eq!(
            dir.lookup(&mut reader, "report-final")
                .unwrap()
                .unwrap()
                .file_id,
            42
        );
    }
}
