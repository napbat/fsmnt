use alloc::string::String;
use alloc::vec::Vec;
use zerocopy::byteorder::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::ChecksumState;
use crate::error::{ExtError, Result};

// fs/ext4/xattr.c:3127, 3128, 3178
const NAME_HASH_SHIFT: u32 = 5;
const VALUE_HASH_SHIFT: u32 = 16;
const BLOCK_HASH_SHIFT: u32 = 16;

/// Xattr magic number (both ibody and block headers).
pub(crate) const XATTR_MAGIC: u32 = 0xEA02_0000;

/// On-disk xattr block header (32 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawXattrBlockHeader {
    /// Magic number: `0xEA020000`.
    h_magic: U32<LE>,
    /// Reference count (block can be shared by multiple inodes).
    h_refcount: U32<LE>,
    /// Number of disk blocks used (always 1).
    h_blocks: U32<LE>,
    /// Hash of all xattrs in this block.
    h_hash: U32<LE>,
    /// CRC32C checksum (when metadata checksums enabled).
    h_checksum: U32<LE>,
    /// Reserved (12 bytes).
    _reserved: [u8; 12],
}

const _: () = assert!(
    core::mem::size_of::<RawXattrBlockHeader>() == 32,
    "RawXattrBlockHeader must be exactly 32 bytes"
);

/// On-disk xattr entry header (16 bytes, followed by variable-length name).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawXattrEntry {
    /// Length of the attribute name suffix in bytes.
    e_name_len: u8,
    /// Name index (prefix selector).
    e_name_index: u8,
    /// Byte offset of the value (base depends on ibody vs block).
    e_value_offs: U16<LE>,
    /// Inode number storing the value (0 = inline).
    e_value_inum: U32<LE>,
    /// Size of the attribute value in bytes.
    e_value_size: U32<LE>,
    /// Hash of the attribute name and value.
    e_hash: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawXattrEntry>() == 16,
    "RawXattrEntry must be exactly 16 bytes"
);

/// Round `n` up to the next 4-byte boundary.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Decode the namespace prefix from an `e_name_index` byte.
///
/// Returns the string prefix that is prepended to `e_name` to form the
/// full attribute name. Indices 2, 3, and 8 are complete names (the
/// suffix is empty). Index 5 is unassigned. Index 9 (`encryption.`)
/// holds fscrypt context xattrs (`encryption.c`).
fn namespace_prefix(index: u8) -> Option<&'static str> {
    match index {
        0 => Some(""),
        1 => Some("user."),
        2 => Some("system.posix_acl_access"),
        3 => Some("system.posix_acl_default"),
        4 => Some("trusted."),
        6 => Some("security."),
        7 => Some("system."),
        8 => Some("system.richacl"),
        9 => Some("encryption."),
        _ => None,
    }
}

/// A single extended attribute entry.
#[derive(Clone, Debug)]
pub struct Xattr {
    name: String,
    value: Vec<u8>,
    ea_inode: u32,
    ea_value_size: u32,
}

impl Xattr {
    /// Full attribute name (prefix + suffix), e.g., `"user.myattr"`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw value bytes.
    ///
    /// Empty when the value is stored in a separate EA inode
    /// ([`ea_inode()`](Self::ea_inode) returns `Some`).
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// EA inode number, if the value is stored externally.
    ///
    /// Returns `None` when the value is inline (available via
    /// [`value()`](Self::value)).
    pub fn ea_inode(&self) -> Option<u32> {
        if self.ea_inode != 0 {
            Some(self.ea_inode)
        } else {
            None
        }
    }

    /// Declared value size from the xattr entry (`e_value_size`).
    ///
    /// For EA inode entries, this is the authoritative length declared
    /// in the xattr descriptor. Used for cross-checking against the
    /// EA inode's `i_size`.
    pub(crate) fn ea_value_size(&self) -> u32 {
        self.ea_value_size
    }

    /// Set the resolved value for an EA inode xattr.
    pub(crate) fn resolve_ea_value(&mut self, value: Vec<u8>) {
        self.value = value;
    }
}

/// Result of a single-name xattr lookup.
#[derive(Debug)]
pub(crate) enum XattrLookup {
    /// No entry with that name exists.
    NotFound,
    /// Entry found with an inline value.
    Found(Vec<u8>),
    /// Entry found but value is in a separate EA inode.
    EaInode { inum: u32, value_size: u32 },
}

/// Check whether `prefix + suffix` matches `target` without allocating.
fn entry_name_matches(prefix: &str, suffix: &[u8], target: &str) -> bool {
    let Some(rest) = target.strip_prefix(prefix) else {
        return false;
    };
    rest.len() == suffix.len() && rest.as_bytes() == suffix
}

/// Look up a single xattr by full name in an ibody region.
pub(crate) fn find_ibody_entry(ibody: &[u8], inode: u32, name: &str) -> Result<XattrLookup> {
    if !has_ibody_magic(ibody) {
        return Ok(XattrLookup::NotFound);
    }
    find_entry(ibody, 4, 4, inode, name)
}

/// Look up a single xattr by full name in an external xattr block.
pub(crate) fn find_block_entry(block: &[u8], inode: u32, name: &str) -> Result<XattrLookup> {
    validate_block_header(block, inode)?;
    let header_size = core::mem::size_of::<RawXattrBlockHeader>();
    find_entry(block, header_size, 0, inode, name)
}

/// Look up a single xattr by raw `(name_index, suffix)` in an ibody
/// region.
///
/// Unlike [`find_ibody_entry`], this keys on the on-disk name index
/// and suffix bytes directly, without translating through
/// [`namespace_prefix`]. Required for namespaces that have no string
/// prefix mapping — notably `EXT4_XATTR_INDEX_VERITY` (11), whose
/// descriptor-location xattr has an empty name.
pub(crate) fn find_ibody_entry_raw(
    ibody: &[u8],
    inode: u32,
    name_index: u8,
    name: &[u8],
) -> Result<XattrLookup> {
    if !has_ibody_magic(ibody) {
        return Ok(XattrLookup::NotFound);
    }
    find_entry_raw(ibody, 4, 4, inode, name_index, name)
}

/// Look up a single xattr by raw `(name_index, suffix)` in an external
/// xattr block. See [`find_ibody_entry_raw`].
pub(crate) fn find_block_entry_raw(
    block: &[u8],
    inode: u32,
    name_index: u8,
    name: &[u8],
) -> Result<XattrLookup> {
    validate_block_header(block, inode)?;
    let header_size = core::mem::size_of::<RawXattrBlockHeader>();
    find_entry_raw(block, header_size, 0, inode, name_index, name)
}

/// Raw-keyed single-entry scan shared by the `*_raw` lookups.
fn find_entry_raw(
    buf: &[u8],
    entries_start: usize,
    value_base: usize,
    inode: u32,
    name_index: u8,
    target: &[u8],
) -> Result<XattrLookup> {
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    let buf_len = buf.len();
    let mut pos = entries_start;

    while let Some(entry) = next_entry(buf, pos, inode)? {
        let name_len = entry.e_name_len as usize;
        let name_start = pos + entry_size;
        if name_start + name_len > buf_len {
            return Err(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name extends past buffer",
            });
        }

        let suffix = &buf[name_start..name_start + name_len];
        if entry.e_name_index == name_index && suffix == target {
            if entry.e_value_inum.get() != 0 {
                return Ok(XattrLookup::EaInode {
                    inum: entry.e_value_inum.get(),
                    value_size: entry.e_value_size.get(),
                });
            }
            let e_value_offs = entry.e_value_offs.get() as usize;
            let e_value_size = entry.e_value_size.get() as usize;
            let value_start = value_base + e_value_offs;
            if value_start + e_value_size > buf_len {
                return Err(ExtError::InvalidXattrBlock {
                    inode,
                    reason: "value extends past buffer",
                });
            }
            return Ok(XattrLookup::Found(
                buf[value_start..value_start + e_value_size].to_vec(),
            ));
        }

        pos = align4(name_start + name_len);
    }

    Ok(XattrLookup::NotFound)
}

/// Check the 4-byte ibody xattr magic. Returns `false` when the
/// region is too short or the magic doesn't match.
fn has_ibody_magic(ibody: &[u8]) -> bool {
    if ibody.len() < 8 {
        return false;
    }
    let magic = U32::<LE>::ref_from_bytes(&ibody[..4])
        .expect("4 bytes always parses")
        .get();
    magic == XATTR_MAGIC
}

/// Validate a block xattr header: length, magic, and h_blocks == 1.
fn validate_block_header(block: &[u8], inode: u32) -> Result<()> {
    let header = RawXattrBlockHeader::ref_from_bytes(
        block
            .get(..core::mem::size_of::<RawXattrBlockHeader>())
            .ok_or(ExtError::InvalidXattrBlock {
                inode,
                reason: "block too short for header",
            })?,
    )
    .map_err(|_| ExtError::InvalidXattrBlock {
        inode,
        reason: "block too short for header",
    })?;

    if header.h_magic.get() != XATTR_MAGIC {
        return Err(ExtError::InvalidXattrBlock {
            inode,
            reason: "bad xattr block magic",
        });
    }
    if header.h_blocks.get() != 1 {
        return Err(ExtError::InvalidXattrBlock {
            inode,
            reason: "h_blocks must be 1",
        });
    }
    Ok(())
}

/// Try to parse a `RawXattrEntry` at `pos` in `buf`.
///
/// Returns `None` at end-of-list (terminator or buffer end), or
/// `Err` on a truncated entry.
fn next_entry(buf: &[u8], pos: usize, inode: u32) -> Result<Option<&RawXattrEntry>> {
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    if pos + 2 > buf.len() {
        return Ok(None);
    }
    if buf[pos] == 0 && buf[pos + 1] == 0 {
        return Ok(None);
    }
    RawXattrEntry::ref_from_bytes(buf.get(pos..pos + entry_size).ok_or(
        ExtError::InvalidXattrBlock {
            inode,
            reason: "truncated entry header",
        },
    )?)
    .map(Some)
    .map_err(|_| ExtError::InvalidXattrBlock {
        inode,
        reason: "truncated entry header",
    })
}

/// Shared single-entry scan. Short-circuits on the first name match
/// and only allocates the matched value.
fn find_entry(
    buf: &[u8],
    entries_start: usize,
    value_base: usize,
    inode: u32,
    target: &str,
) -> Result<XattrLookup> {
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    let buf_len = buf.len();
    let mut pos = entries_start;

    while let Some(entry) = next_entry(buf, pos, inode)? {
        let name_len = entry.e_name_len as usize;
        let name_start = pos + entry_size;
        if name_start + name_len > buf_len {
            return Err(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name extends past buffer",
            });
        }

        if let Some(prefix) = namespace_prefix(entry.e_name_index) {
            let suffix = &buf[name_start..name_start + name_len];
            if entry_name_matches(prefix, suffix, target) {
                if entry.e_value_inum.get() != 0 {
                    return Ok(XattrLookup::EaInode {
                        inum: entry.e_value_inum.get(),
                        value_size: entry.e_value_size.get(),
                    });
                }
                let e_value_offs = entry.e_value_offs.get() as usize;
                let e_value_size = entry.e_value_size.get() as usize;
                let value_start = value_base + e_value_offs;
                if value_start + e_value_size > buf_len {
                    return Err(ExtError::InvalidXattrBlock {
                        inode,
                        reason: "value extends past buffer",
                    });
                }
                return Ok(XattrLookup::Found(
                    buf[value_start..value_start + e_value_size].to_vec(),
                ));
            }
        }

        pos = align4(name_start + name_len);
    }

    Ok(XattrLookup::NotFound)
}

/// Parse xattr entries from an ibody region (in-inode xattrs).
///
/// `ibody` starts with the 4-byte magic header. Entries begin at
/// offset 4. Value offsets (`e_value_offs`) are relative to offset 4
/// (the first entry). Appends parsed entries to `out`.
pub(crate) fn parse_ibody_entries(ibody: &[u8], inode: u32, out: &mut Vec<Xattr>) -> Result<()> {
    if !has_ibody_magic(ibody) {
        return Ok(());
    }
    parse_entries(ibody, 4, 4, inode, out)
}

/// Parse xattr entries from an external xattr block.
///
/// `block` is the full block contents (one filesystem block). The
/// first 32 bytes are the `ext4_xattr_header`. Entries begin at
/// offset 32. Value offsets (`e_value_offs`) are relative to the
/// block start (offset 0).
pub(crate) fn parse_block_entries(block: &[u8], inode: u32, out: &mut Vec<Xattr>) -> Result<()> {
    validate_block_header(block, inode)?;
    let header_size = core::mem::size_of::<RawXattrBlockHeader>();
    parse_entries(block, header_size, 0, inode, out)
}

/// Shared entry-parsing loop for both ibody and block xattr regions.
fn parse_entries(
    buf: &[u8],
    entries_start: usize,
    value_base: usize,
    inode: u32,
    out: &mut Vec<Xattr>,
) -> Result<()> {
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    let buf_len = buf.len();
    let mut pos = entries_start;

    while let Some(entry) = next_entry(buf, pos, inode)? {
        let name_len = entry.e_name_len as usize;
        let name_start = pos + entry_size;
        if name_start + name_len > buf_len {
            return Err(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name extends past buffer",
            });
        }

        let prefix = match namespace_prefix(entry.e_name_index) {
            Some(p) => p,
            None => {
                pos = align4(name_start + name_len);
                continue;
            }
        };

        let suffix = &buf[name_start..name_start + name_len];
        let mut name = String::with_capacity(prefix.len() + suffix.len());
        name.push_str(prefix);
        for &b in suffix {
            name.push(b as char);
        }

        let e_value_inum = entry.e_value_inum.get();
        let e_value_size_raw = entry.e_value_size.get();
        let (value, ea_inode_num) = if e_value_inum != 0 {
            (Vec::new(), e_value_inum)
        } else {
            let e_value_offs = entry.e_value_offs.get() as usize;
            let e_value_size = e_value_size_raw as usize;
            let value_start = value_base + e_value_offs;
            if value_start + e_value_size > buf_len {
                return Err(ExtError::InvalidXattrBlock {
                    inode,
                    reason: "value extends past buffer",
                });
            }
            (buf[value_start..value_start + e_value_size].to_vec(), 0)
        };

        out.push(Xattr {
            name,
            value,
            ea_inode: ea_inode_num,
            ea_value_size: e_value_size_raw,
        });

        pos = align4(name_start + name_len);
    }

    Ok(())
}

/// Per-entry `e_hash` validation result. The `name` field is the
/// fully-prefixed attribute name (matches [`Xattr::name`]); `state`
/// reports the per-entry hash validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrEntryHashStatus {
    /// Full attribute name (prefix + suffix).
    pub name: String,
    /// `Valid` when the on-disk `e_hash` matches the kernel's
    /// `ext4_xattr_hash_entry` (or `ext4_xattr_hash_entry_signed`
    /// fallback for filesystems created with the legacy signed
    /// formula). `Unknown` for EA-inode-backed entries whose hash
    /// requires reading the EA inode body. `Invalid` otherwise.
    pub state: ChecksumState,
}

/// Aggregate diagnostic for an external xattr block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrBlockHashReport {
    /// Whether the on-disk `h_hash` matches the kernel's
    /// `ext4_xattr_rehash` formula over the entries' on-disk
    /// `e_hash` values.
    pub block_hash: ChecksumState,
    /// Per-entry validation results, in on-disk entry order.
    pub entries: Vec<XattrEntryHashStatus>,
}

/// Compute the ext4 xattr entry hash with the kernel's unsigned-char
/// formula. Mirrors `ext4_xattr_hash_entry` at `fs/ext4/xattr.c:3127-3149`.
pub(crate) fn xattr_hash_entry(name: &[u8], value_words: &[u32]) -> u32 {
    let mut hash: u32 = 0;
    for &b in name {
        // (hash << 5) ^ (hash >> 27) ^ (unsigned char)*name
        hash = hash.rotate_left(NAME_HASH_SHIFT) ^ u32::from(b);
    }
    for &w in value_words {
        hash = hash.rotate_left(VALUE_HASH_SHIFT) ^ w;
    }
    hash
}

/// Compute the legacy buggy xattr entry hash with the kernel's
/// signed-char formula. Mirrors `ext4_xattr_hash_entry_signed` at
/// `fs/ext4/xattr.c:3155-3174`; accepted as a fallback against
/// filesystems built by older kernels that used the buggy cast.
pub(crate) fn xattr_hash_entry_signed(name: &[u8], value_words: &[u32]) -> u32 {
    let mut hash: u32 = 0;
    for &b in name {
        // (signed char)*name sign-extends through `int` to u32.
        let signed_word = i32::from(b as i8) as u32;
        hash = hash.rotate_left(NAME_HASH_SHIFT) ^ signed_word;
    }
    for &w in value_words {
        hash = hash.rotate_left(VALUE_HASH_SHIFT) ^ w;
    }
    hash
}

/// Compute the ext4 xattr block hash. Mirrors `ext4_xattr_rehash` at
/// `fs/ext4/xattr.c:3183-3204`; if any per-entry hash is zero, the
/// kernel forces `h_hash = 0` to mark the block as non-shareable.
pub(crate) fn xattr_block_hash<I: IntoIterator<Item = u32>>(entry_hashes: I) -> u32 {
    let mut hash: u32 = 0;
    for e in entry_hashes {
        if e == 0 {
            // "Block is not shared if an entry's hash value == 0"
            // (xattr.c:3195) — kernel breaks out and emits h_hash = 0.
            return 0;
        }
        hash = hash.rotate_left(BLOCK_HASH_SHIFT) ^ e;
    }
    hash
}

/// Pack a value byte slice into u32 LE words, zero-padding the
/// trailing partial word.
///
/// The kernel reads from the in-block value slot which is always
/// 4-byte-aligned; bytes past `e_value_size` are zero on disk.
fn read_value_words(bytes: &[u8]) -> Vec<u32> {
    let word_count = bytes.len().div_ceil(4);
    let mut out = Vec::with_capacity(word_count);
    for chunk_idx in 0..word_count {
        let start = chunk_idx * 4;
        let end = (start + 4).min(bytes.len());
        let mut buf = [0u8; 4];
        buf[..end - start].copy_from_slice(&bytes[start..end]);
        out.push(u32::from_le_bytes(buf));
    }
    out
}

/// Validate the `h_hash` and per-entry `e_hash` fields of an external
/// xattr block.
///
/// EA-inode-backed entries (`e_value_inum != 0`) report
/// [`ChecksumState::Unknown`] — verifying their `e_hash` requires
/// reading the EA inode body and CRC32C-hashing it, which is out of
/// the read-side primitive here. Block hash is always `Valid` /
/// `Invalid` because it depends only on the on-disk `e_hash` bytes.
pub fn verify_xattr_block_hashes(block: &[u8], inode: u32) -> Result<XattrBlockHashReport> {
    validate_block_header(block, inode)?;
    let header_size = core::mem::size_of::<RawXattrBlockHeader>();
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    let mut entries = Vec::new();
    let mut on_disk_hashes = Vec::new();
    let mut pos = header_size;
    let value_base = 0usize;

    while let Some(entry) = next_entry(block, pos, inode)? {
        let name_len = entry.e_name_len as usize;
        let name_start = pos + entry_size;
        if name_start + name_len > block.len() {
            return Err(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name extends past buffer",
            });
        }
        let name_bytes = &block[name_start..name_start + name_len];
        let prefix = namespace_prefix(entry.e_name_index).unwrap_or("");
        let mut name = String::with_capacity(prefix.len() + name_bytes.len());
        name.push_str(prefix);
        for &b in name_bytes {
            name.push(b as char);
        }

        let on_disk_e = entry.e_hash.get();
        on_disk_hashes.push(on_disk_e);

        let state = if entry.e_value_inum.get() != 0 {
            ChecksumState::Unknown
        } else {
            let value_offs = entry.e_value_offs.get() as usize;
            let value_size = entry.e_value_size.get() as usize;
            // fs/ext4/xattr.c:1823-1830 — kernel hashes `EXT4_XATTR_SIZE(size)`
            // bytes (the 4-byte-padded slot) as `new_size >> 2` u32 words.
            // Reading the actual padded bytes from disk surfaces corrupted
            // non-zero padding as `Invalid` instead of accepting it as `Valid`
            // via a synthesized zero pad.
            let padded_size = align4(value_size);
            let value_start = value_base + value_offs;
            if value_start + padded_size > block.len() {
                return Err(ExtError::InvalidXattrBlock {
                    inode,
                    reason: "value extends past buffer",
                });
            }
            let words = read_value_words(&block[value_start..value_start + padded_size]);
            let computed = xattr_hash_entry(name_bytes, &words);
            let computed_signed = xattr_hash_entry_signed(name_bytes, &words);
            // xattr.c:496-517: kernel accepts either the unsigned or
            // signed-fallback form (the latter logs a one-shot warning).
            if computed == on_disk_e || computed_signed == on_disk_e {
                ChecksumState::Valid
            } else {
                ChecksumState::Invalid
            }
        };

        entries.push(XattrEntryHashStatus { name, state });
        pos = align4(name_start + name_len);
    }

    let on_disk_h = RawXattrBlockHeader::ref_from_bytes(&block[..header_size])
        .expect("validated by validate_block_header")
        .h_hash
        .get();
    let computed_h = xattr_block_hash(on_disk_hashes.iter().copied());
    let block_hash = if computed_h == on_disk_h {
        ChecksumState::Valid
    } else {
        ChecksumState::Invalid
    };

    Ok(XattrBlockHashReport {
        block_hash,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_prefix_known_indices() {
        assert_eq!(namespace_prefix(0), Some(""));
        assert_eq!(namespace_prefix(1), Some("user."));
        assert_eq!(namespace_prefix(2), Some("system.posix_acl_access"));
        assert_eq!(namespace_prefix(3), Some("system.posix_acl_default"));
        assert_eq!(namespace_prefix(4), Some("trusted."));
        assert_eq!(namespace_prefix(6), Some("security."));
        assert_eq!(namespace_prefix(7), Some("system."));
        assert_eq!(namespace_prefix(8), Some("system.richacl"));
    }

    #[test]
    fn namespace_prefix_encryption_index() {
        // EXT4_XATTR_INDEX_ENCRYPTION = 9, prefix maps to "encryption."
        assert_eq!(namespace_prefix(9), Some("encryption."));
    }

    #[test]
    fn namespace_prefix_unassigned() {
        assert_eq!(namespace_prefix(5), None);
        assert_eq!(namespace_prefix(255), None);
    }

    const IBODY_SIZE: usize = 96; // typical: 256 - 128 - 32

    fn ibody_buf() -> Vec<u8> {
        let mut buf = vec![0u8; IBODY_SIZE];
        buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        buf
    }

    fn write_entry(
        buf: &mut [u8],
        pos: usize,
        name_index: u8,
        name: &[u8],
        value_offs: u16,
        value_inum: u32,
        value_size: u32,
    ) -> usize {
        buf[pos] = name.len() as u8;
        buf[pos + 1] = name_index;
        buf[pos + 2..pos + 4].copy_from_slice(&value_offs.to_le_bytes());
        buf[pos + 4..pos + 8].copy_from_slice(&value_inum.to_le_bytes());
        buf[pos + 8..pos + 12].copy_from_slice(&value_size.to_le_bytes());
        buf[pos + 16..pos + 16 + name.len()].copy_from_slice(name);
        align4(pos + 16 + name.len())
    }

    /// Place a value at the end of the free region and return its
    /// offset relative to `value_base`. `tail` tracks the next free
    /// byte (starts at `buf.len()`, moves downward).
    fn place_value(buf: &mut [u8], data: &[u8], value_base: usize, tail: &mut usize) -> u16 {
        let start = *tail - data.len();
        buf[start..start + data.len()].copy_from_slice(data);
        *tail = start;
        (start - value_base) as u16
    }

    #[test]
    fn parse_ibody_single_user_xattr() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let mut tail = buf.len();
        let val = b"hello";
        let offs = place_value(&mut buf, val, first_entry, &mut tail);
        let next = write_entry(
            &mut buf,
            first_entry,
            1,
            b"greeting",
            offs,
            0,
            val.len() as u32,
        );
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_ibody_entries(&buf, 42, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "user.greeting");
        assert_eq!(out[0].value(), b"hello");
        assert!(out[0].ea_inode().is_none());
    }

    #[test]
    fn parse_ibody_encryption_xattr_with_suffix_c() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let mut tail = buf.len();
        // 28-byte v1 fscrypt context as the value
        let val: Vec<u8> = (0..28u8).collect();
        let offs = place_value(&mut buf, &val, first_entry, &mut tail);
        let next = write_entry(&mut buf, first_entry, 9, b"c", offs, 0, val.len() as u32);
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_ibody_entries(&buf, 42, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "encryption.c");
        assert_eq!(out[0].value(), val.as_slice());
    }

    #[test]
    fn parse_ibody_multiple_namespaces() {
        let big = 200usize;
        let mut buf = vec![0u8; big];
        buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        let first_entry = 4usize;
        let mut tail = buf.len();

        let v1 = b"unconfined_t";
        let o1 = place_value(&mut buf, v1, first_entry, &mut tail);
        let next = write_entry(&mut buf, first_entry, 6, b"selinux", o1, 0, v1.len() as u32);

        let v2 = b"myval";
        let o2 = place_value(&mut buf, v2, first_entry, &mut tail);
        let next = write_entry(&mut buf, next, 1, b"tag", o2, 0, v2.len() as u32);

        let v3 = b"sysdata";
        let o3 = place_value(&mut buf, v3, first_entry, &mut tail);
        let next = write_entry(&mut buf, next, 7, b"data", o3, 0, v3.len() as u32);
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_ibody_entries(&buf, 10, &mut out).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].name(), "security.selinux");
        assert_eq!(out[0].value(), b"unconfined_t");
        assert_eq!(out[1].name(), "user.tag");
        assert_eq!(out[1].value(), b"myval");
        assert_eq!(out[2].name(), "system.data");
        assert_eq!(out[2].value(), b"sysdata");
    }

    #[test]
    fn parse_ibody_ea_inode_entry() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let next = write_entry(&mut buf, first_entry, 1, b"big", 0, 500, 65536);
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_ibody_entries(&buf, 42, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "user.big");
        assert!(out[0].value().is_empty());
        assert_eq!(out[0].ea_inode(), Some(500));
    }

    #[test]
    fn parse_ibody_no_magic_returns_empty() {
        let buf = vec![0u8; IBODY_SIZE];
        let mut out = Vec::new();
        parse_ibody_entries(&buf, 42, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_ibody_unknown_name_index_skips_entry() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let mut tail = buf.len();
        let val = b"test";
        let offs = place_value(&mut buf, val, first_entry, &mut tail);
        let next = write_entry(
            &mut buf,
            first_entry,
            5,
            b"weird",
            offs,
            0,
            val.len() as u32,
        );
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_ibody_entries(&buf, 42, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn find_ibody_entry_found() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let mut tail = buf.len();
        let val = b"hello";
        let offs = place_value(&mut buf, val, first_entry, &mut tail);
        let next = write_entry(
            &mut buf,
            first_entry,
            1,
            b"greeting",
            offs,
            0,
            val.len() as u32,
        );
        buf[next] = 0;
        buf[next + 1] = 0;

        let result = find_ibody_entry(&buf, 42, "user.greeting").unwrap();
        match result {
            XattrLookup::Found(v) => assert_eq!(v, b"hello"),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn find_ibody_entry_not_found() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let mut tail = buf.len();
        let val = b"hello";
        let offs = place_value(&mut buf, val, first_entry, &mut tail);
        let next = write_entry(
            &mut buf,
            first_entry,
            1,
            b"greeting",
            offs,
            0,
            val.len() as u32,
        );
        buf[next] = 0;
        buf[next + 1] = 0;

        let result = find_ibody_entry(&buf, 42, "user.other").unwrap();
        assert!(matches!(result, XattrLookup::NotFound));
    }

    #[test]
    fn find_ibody_entry_ea_inode() {
        let mut buf = ibody_buf();
        let first_entry = 4usize;
        let next = write_entry(&mut buf, first_entry, 1, b"big", 0, 500, 65536);
        buf[next] = 0;
        buf[next + 1] = 0;

        let result = find_ibody_entry(&buf, 42, "user.big").unwrap();
        assert!(matches!(
            result,
            XattrLookup::EaInode {
                inum: 500,
                value_size: 65536,
            }
        ));
    }

    #[test]
    fn entry_name_matches_works() {
        assert!(entry_name_matches("user.", b"greeting", "user.greeting"));
        assert!(!entry_name_matches("user.", b"greeting", "user.other"));
        assert!(!entry_name_matches("security.", b"selinux", "user.selinux"));
        assert!(entry_name_matches("", b"raw", "raw"));
        assert!(entry_name_matches(
            "system.posix_acl_access",
            b"",
            "system.posix_acl_access"
        ));
    }

    fn block_buf(size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        buf[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // h_refcount = 1
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // h_blocks = 1
        buf
    }

    #[test]
    fn parse_block_single_entry() {
        let bsize = 4096usize;
        let mut buf = block_buf(bsize);

        let val = b"block_value";
        let start = bsize - val.len();
        buf[start..start + val.len()].copy_from_slice(val);
        let offs = start as u16;

        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        let next = write_entry(
            &mut buf,
            entries_off,
            1,
            b"attr1",
            offs,
            0,
            val.len() as u32,
        );
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_block_entries(&buf, 42, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "user.attr1");
        assert_eq!(out[0].value(), b"block_value");
    }

    #[test]
    fn parse_block_bad_magic() {
        let mut buf = vec![0u8; 4096];
        buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let mut out = Vec::new();
        let err = parse_block_entries(&buf, 42, &mut out).unwrap_err();
        match err {
            ExtError::InvalidXattrBlock { inode: 42, .. } => {}
            other => panic!("expected InvalidXattrBlock, got {other:?}"),
        }
    }

    #[test]
    fn parse_block_bad_h_blocks() {
        let mut buf = block_buf(4096);
        buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // h_blocks = 2 (must be 1)

        let mut out = Vec::new();
        let err = parse_block_entries(&buf, 99, &mut out).unwrap_err();
        match err {
            ExtError::InvalidXattrBlock { inode: 99, .. } => {}
            other => panic!("expected InvalidXattrBlock, got {other:?}"),
        }
    }

    #[test]
    fn parse_block_too_short() {
        let buf = vec![0u8; 16];
        let mut out = Vec::new();
        let err = parse_block_entries(&buf, 1, &mut out).unwrap_err();
        match err {
            ExtError::InvalidXattrBlock { inode: 1, .. } => {}
            other => panic!("expected InvalidXattrBlock, got {other:?}"),
        }
    }

    // ---- xattr hash primitives ----

    #[test]
    fn hash_entry_unsigned_matches_kernel_walk_through_for_u_dot_x() {
        // fs/ext4/xattr.c:3127-3149. Name "u.x" (0x75 0x2e 0x78), no values.
        //   hash = (0 << 5) ^ (0 >> 27) ^ 0x75 = 0x75
        //   hash = (0x75 << 5) ^ (0x75 >> 27) ^ 0x2e = 0xEA0 ^ 0x2e = 0xE8E
        //   hash = (0xE8E << 5) ^ (0xE8E >> 27) ^ 0x78 = 0x1D1C0 ^ 0x78 = 0x1D1B8
        assert_eq!(xattr_hash_entry(b"u.x", &[]), 0x0001_D1B8);
    }

    #[test]
    fn hash_entry_unsigned_vs_signed_diverge_on_high_byte_names() {
        // Single byte 0x80; no value.
        // Unsigned: hash = 0 ^ 0x80 = 0x80
        // Signed:   (i8)0x80 = -128 → sign-extended → 0xFFFF_FF80
        assert_eq!(xattr_hash_entry(b"\x80", &[]), 0x0000_0080);
        assert_eq!(xattr_hash_entry_signed(b"\x80", &[]), 0xFFFF_FF80);
    }

    #[test]
    fn hash_entry_walks_value_words() {
        // "x" (0x78) + 1 value word 0x1111_2222.
        //   hash = 0 ^ 0x78 = 0x78
        //   hash = (0x78 << 16) ^ (0x78 >> 16) ^ 0x1111_2222
        //        = 0x0078_0000 ^ 0x0000_0000 ^ 0x1111_2222 = 0x1169_2222
        assert_eq!(xattr_hash_entry(b"x", &[0x1111_2222]), 0x1169_2222);
    }

    #[test]
    fn block_hash_zero_if_any_entry_hash_zero() {
        // xattr.c:3194-3196 — any zero e_hash forces h_hash = 0.
        assert_eq!(xattr_block_hash([0x0000_0001, 0, 0x0000_0002]), 0);
    }

    #[test]
    fn block_hash_empty_is_zero() {
        assert_eq!(xattr_block_hash([0u32; 0]), 0);
    }

    #[test]
    fn block_hash_accumulates_per_entry() {
        // hash = 0
        // e=0x1234_5678 → 0x1234_5678
        // e=0xCAFE_BABE → rotl(0x1234_5678, 16) ^ 0xCAFE_BABE
        //               = 0x5678_1234 ^ 0xCAFE_BABE = 0x9C86_A88A
        assert_eq!(xattr_block_hash([0x1234_5678, 0xCAFE_BABE]), 0x9C86_A88A);
    }

    // ---- verify_xattr_block_hashes ----

    /// Build a block with a single inline user.attr entry whose value
    /// is `value` and whose e_hash + h_hash are computed honestly.
    fn build_block_with_one_inline_entry(
        bsize: usize,
        name_index: u8,
        name: &[u8],
        value: &[u8],
    ) -> Vec<u8> {
        let mut buf = block_buf(bsize);
        // Allocate the EXT4_XATTR_SIZE(value_size) slot at the block tail
        // and write the value bytes at the slot start. The trailing
        // 0..3 bytes are the zero-padding the kernel writes on disk.
        let padded_len = align4(value.len());
        let slot_start = bsize - padded_len;
        buf[slot_start..slot_start + value.len()].copy_from_slice(value);

        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        // Write the entry header first, with placeholder e_hash, then patch.
        let _next = write_entry(
            &mut buf,
            entries_off,
            name_index,
            name,
            slot_start as u16,
            0,
            value.len() as u32,
        );
        // Hash over the actual padded slot (including any padding bytes),
        // matching `verify_xattr_block_hashes`.
        let words = read_value_words(&buf[slot_start..slot_start + padded_len]);
        let e_hash = xattr_hash_entry(name, &words);
        buf[entries_off + 12..entries_off + 16].copy_from_slice(&e_hash.to_le_bytes());

        // Compute and plant h_hash.
        let h_hash = xattr_block_hash([e_hash]);
        buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

        buf
    }

    #[test]
    fn verify_block_clean_block_reports_valid() {
        let buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        assert_eq!(report.block_hash, ChecksumState::Valid);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "user.attr1");
        assert_eq!(report.entries[0].state, ChecksumState::Valid);
    }

    #[test]
    fn verify_block_corrupted_value_byte_invalid_entry() {
        let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        // Flip a byte in the value (which sits at end of block).
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        assert_eq!(report.entries[0].state, ChecksumState::Invalid);
        // Block hash uses the on-disk e_hash, which we didn't touch, so
        // h_hash remains Valid.
        assert_eq!(report.block_hash, ChecksumState::Valid);
    }

    #[test]
    fn verify_block_corrupted_padding_byte_invalidates_entry() {
        // Regression for the e_hash padding bug: ext4 hashes
        // `EXT4_XATTR_SIZE(e_value_size)` bytes (fs/ext4/xattr.c:1823-1830),
        // so non-zero padding bytes in the value slot must cause the
        // computed hash to diverge from the on-disk e_hash. Earlier
        // versions of `verify_xattr_block_hashes` synthesized zero
        // padding and reported such blocks as `Valid` by mistake.
        let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        // "hello" is 5 bytes, padded slot is 8. Slot end byte
        // (`bsize-1`) is the last byte of the padding region and was
        // planted as zero by the helper.
        let bsize = buf.len();
        buf[bsize - 1] = 0xAB;
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        assert_eq!(report.entries[0].state, ChecksumState::Invalid);
    }

    #[test]
    fn verify_block_corrupted_name_byte_invalid_entry() {
        let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        // Mutate the first byte of the entry name.
        buf[entries_off + 16] ^= 0x01;
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        assert_eq!(report.entries[0].state, ChecksumState::Invalid);
    }

    #[test]
    fn verify_block_corrupted_on_disk_e_hash_byte_invalidates_both() {
        let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        // Flip the on-disk e_hash low byte.
        buf[entries_off + 12] ^= 0x01;
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        // The computed e_hash from name+value no longer matches the
        // (corrupted) on-disk value.
        assert_eq!(report.entries[0].state, ChecksumState::Invalid);
        // And since the block hash chain uses the corrupted on-disk
        // e_hash, the recomputed h_hash diverges from the (still
        // correctly-planted) h_hash header bytes.
        assert_eq!(report.block_hash, ChecksumState::Invalid);
    }

    #[test]
    fn verify_block_corrupted_h_hash_byte_invalidates_block_only() {
        let mut buf = build_block_with_one_inline_entry(4096, 1, b"attr1", b"hello");
        // Flip the on-disk h_hash low byte.
        buf[12] ^= 0x01;
        let report = verify_xattr_block_hashes(&buf, 99).unwrap();
        assert_eq!(report.entries[0].state, ChecksumState::Valid);
        assert_eq!(report.block_hash, ChecksumState::Invalid);
    }

    #[test]
    fn verify_block_ea_inode_entry_reports_unknown() {
        let bsize = 4096usize;
        let mut buf = block_buf(bsize);
        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        // EA-inode-backed: e_value_inum nonzero, e_value_size set, no inline value.
        let _next = write_entry(&mut buf, entries_off, 1, b"big", 0, 500, 65_536);
        // Plant a nonsense on-disk e_hash; verify path should still
        // report `Unknown` because the value isn't readable inline.
        buf[entries_off + 12..entries_off + 16].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // Plant the matching h_hash from the on-disk e_hash chain.
        let h_hash = xattr_block_hash([0xDEAD_BEEFu32]);
        buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

        let report = verify_xattr_block_hashes(&buf, 7).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "user.big");
        assert_eq!(report.entries[0].state, ChecksumState::Unknown);
        assert_eq!(report.block_hash, ChecksumState::Valid);
    }

    #[test]
    fn verify_block_two_entry_round_trip() {
        let bsize = 4096usize;
        let mut buf = block_buf(bsize);
        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();

        // Entry 1: user.a = "1"
        let v1 = b"1";
        let s1 = bsize - 4; // 4-byte slot
        buf[s1..s1 + v1.len()].copy_from_slice(v1);
        let next = write_entry(
            &mut buf,
            entries_off,
            1,
            b"a",
            s1 as u16,
            0,
            v1.len() as u32,
        );
        let words1 = read_value_words(v1);
        let e_hash1 = xattr_hash_entry(b"a", &words1);
        buf[entries_off + 12..entries_off + 16].copy_from_slice(&e_hash1.to_le_bytes());

        // Entry 2: trusted.cap = "two"
        let v2 = b"two";
        let s2 = s1 - 4;
        buf[s2..s2 + v2.len()].copy_from_slice(v2);
        let entry2_pos = next;
        let _next2 = write_entry(
            &mut buf,
            entry2_pos,
            4,
            b"cap",
            s2 as u16,
            0,
            v2.len() as u32,
        );
        let words2 = read_value_words(v2);
        let e_hash2 = xattr_hash_entry(b"cap", &words2);
        buf[entry2_pos + 12..entry2_pos + 16].copy_from_slice(&e_hash2.to_le_bytes());

        let h_hash = xattr_block_hash([e_hash1, e_hash2]);
        buf[12..16].copy_from_slice(&h_hash.to_le_bytes());

        let report = verify_xattr_block_hashes(&buf, 5).unwrap();
        assert_eq!(report.block_hash, ChecksumState::Valid);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].name, "user.a");
        assert_eq!(report.entries[0].state, ChecksumState::Valid);
        assert_eq!(report.entries[1].name, "trusted.cap");
        assert_eq!(report.entries[1].state, ChecksumState::Valid);
    }

    #[test]
    fn parse_block_multiple_entries() {
        let bsize = 4096usize;
        let mut buf = block_buf(bsize);

        let v1 = b"val_one";
        let s1 = bsize - v1.len();
        buf[s1..s1 + v1.len()].copy_from_slice(v1);

        let v2 = b"val_two";
        let s2 = s1 - v2.len();
        buf[s2..s2 + v2.len()].copy_from_slice(v2);

        let entries_off = core::mem::size_of::<RawXattrBlockHeader>();
        let next = write_entry(
            &mut buf,
            entries_off,
            6,
            b"selinux",
            s1 as u16,
            0,
            v1.len() as u32,
        );
        let next = write_entry(&mut buf, next, 4, b"cap", s2 as u16, 0, v2.len() as u32);
        buf[next] = 0;
        buf[next + 1] = 0;

        let mut out = Vec::new();
        parse_block_entries(&buf, 5, &mut out).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name(), "security.selinux");
        assert_eq!(out[1].name(), "trusted.cap");
    }
}
