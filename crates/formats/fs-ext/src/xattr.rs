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
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical ext4 e_* xattr identifiers"
)]
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
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw value bytes.
    ///
    /// Empty when the value is stored in a separate EA inode
    /// ([`ea_inode()`](Self::ea_inode) returns `Some`).
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// EA inode number, if the value is stored externally.
    ///
    /// Returns `None` when the value is inline (available via
    /// [`value()`](Self::value)).
    #[must_use]
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

/// Validate a block xattr header: length, magic, and `h_blocks` == 1.
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

        let Some(prefix) = namespace_prefix(entry.e_name_index) else {
            pos = align4(name_start + name_len);
            continue;
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
        let signed_word = i32::from(b.cast_signed()).cast_unsigned();
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
///
/// # Errors
///
/// Returns [`ExtError::InvalidXattrBlock`] when the header, entries, names,
/// or value ranges are malformed.
pub fn verify_xattr_block_hashes(block: &[u8], inode: u32) -> Result<XattrBlockHashReport> {
    validate_block_header(block, inode)?;
    let header_size = core::mem::size_of::<RawXattrBlockHeader>();
    let entry_size = core::mem::size_of::<RawXattrEntry>();
    let mut entries = Vec::new();
    let mut on_disk_hashes = Vec::new();
    let mut pos = header_size;
    let value_base = 0usize;

    while let Some(entry) = next_entry(block, pos, inode)? {
        let name_len = usize::from(entry.e_name_len);
        let name_start = pos
            .checked_add(entry_size)
            .ok_or(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name offset overflow",
            })?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name end overflow",
            })?;
        if name_end > block.len() {
            return Err(ExtError::InvalidXattrBlock {
                inode,
                reason: "entry name extends past buffer",
            });
        }
        let name_bytes = &block[name_start..name_end];
        let prefix = namespace_prefix(entry.e_name_index).unwrap_or("");
        let mut name = String::with_capacity(prefix.len() + name_bytes.len());
        name.push_str(prefix);
        for &b in name_bytes {
            name.push(char::from(b));
        }

        let on_disk_e = entry.e_hash.get();
        on_disk_hashes.push(on_disk_e);

        let state = if entry.e_value_inum.get() != 0 {
            ChecksumState::Unknown
        } else {
            let value_offs = usize::from(entry.e_value_offs.get());
            let value_size = usize::try_from(entry.e_value_size.get()).map_err(|_| {
                ExtError::InvalidXattrBlock {
                    inode,
                    reason: "xattr value size exceeds addressable memory",
                }
            })?;
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
        .map_err(|_| ExtError::InvalidXattrBlock {
            inode,
            reason: "xattr block header failed to parse",
        })?
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
#[path = "xattr_tests/mod.rs"]
mod tests;
