use zerocopy::byteorder::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};

/// On-disk ext4 directory entry with file type byte (`ext4_dir_entry_2`).
///
/// Used when the `FILETYPE` incompat feature is set (ext3/ext4).
/// The `file_type` field encodes the entry's type (1=regular, 2=directory, etc).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawDirEntry2 {
    pub inode: U32<LE>,
    pub rec_len: U16<LE>,
    pub name_len: u8,
    pub file_type: u8,
}

/// On-disk ext2 directory entry without file type byte (`ext4_dir_entry`).
///
/// Used when the `FILETYPE` incompat feature is NOT set (ext2 rev 0).
/// The `name_len` field occupies the full 16 bits (no file type byte).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawDirEntry {
    pub inode: U32<LE>,
    pub rec_len: U16<LE>,
    pub name_len: U16<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawDirEntry2>() == 8,
    "RawDirEntry2 must be exactly 8 bytes"
);

const _: () = assert!(
    core::mem::size_of::<RawDirEntry>() == 8,
    "RawDirEntry must be exactly 8 bytes"
);

/// Parsed information from a single directory entry.
#[derive(Debug)]
pub(crate) struct DirEntryInfo {
    /// Inode number the entry points to.
    pub inode: u32,
    /// Start offset of the name within the directory block buffer.
    pub name_start: usize,
    /// End offset (exclusive) of the name within the directory block buffer.
    pub name_end: usize,
    /// File type byte (0 if the filesystem lacks FILETYPE support).
    pub file_type: u8,
    /// Byte offset of the next entry (current offset + rec_len).
    pub next_offset: usize,
}

/// Minimum directory entry size: 4 (inode) + 2 (rec_len) + 1 (name_len) + 1 (file_type/name_len_hi).
const MIN_DIR_ENTRY_SIZE: u16 = 8;

/// Parse the next valid directory entry from `buf` starting at `offset`.
///
/// Skips entries where inode == 0 (deleted/padding) and "."/"..".
/// Returns `Ok(None)` when `offset >= buf.len()` or `rec_len` would
/// go past `buf`. Returns an error if rec_len or name_len is invalid.
pub(crate) fn parse_next_entry(
    buf: &[u8],
    mut offset: usize,
    has_filetype: bool,
    dir_inode: u32,
) -> Result<Option<DirEntryInfo>> {
    loop {
        if offset + 8 > buf.len() {
            return Ok(None);
        }

        let (inode, rec_len, name_len, file_type) = if has_filetype {
            let raw = RawDirEntry2::ref_from_bytes(&buf[offset..offset + 8]).map_err(|_| {
                ExtError::InvalidDirectoryEntry {
                    inode: dir_inode,
                    offset: offset as u64,
                }
            })?;
            (
                raw.inode.get(),
                raw.rec_len.get(),
                u16::from(raw.name_len),
                raw.file_type,
            )
        } else {
            let raw = RawDirEntry::ref_from_bytes(&buf[offset..offset + 8]).map_err(|_| {
                ExtError::InvalidDirectoryEntry {
                    inode: dir_inode,
                    offset: offset as u64,
                }
            })?;
            (raw.inode.get(), raw.rec_len.get(), raw.name_len.get(), 0u8)
        };

        if rec_len < MIN_DIR_ENTRY_SIZE || rec_len % 4 != 0 {
            return Err(ExtError::InvalidDirectoryEntry {
                inode: dir_inode,
                offset: offset as u64,
            });
        }

        let next_offset = offset + usize::from(rec_len);
        if next_offset > buf.len() {
            return Ok(None);
        }

        let max_name = usize::from(rec_len) - 8;
        if usize::from(name_len) > max_name {
            return Err(ExtError::InvalidDirectoryEntry {
                inode: dir_inode,
                offset: offset as u64,
            });
        }

        // Skip deleted/padding entries (inode == 0).
        if inode == 0 {
            offset = next_offset;
            continue;
        }

        let name_start = offset + 8;
        let name_end = name_start + usize::from(name_len);

        // Skip "." and ".." entries.
        let name = &buf[name_start..name_end];
        if name == b"." || name == b".." {
            offset = next_offset;
            continue;
        }

        return Ok(Some(DirEntryInfo {
            inode,
            name_start,
            name_end,
            file_type,
            next_offset,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a directory entry in a buffer at a given offset.
    fn write_entry(
        buf: &mut [u8],
        off: usize,
        inode: u32,
        rec_len: u16,
        name: &[u8],
        file_type: u8,
        has_filetype: bool,
    ) {
        buf[off..off + 4].copy_from_slice(&inode.to_le_bytes());
        buf[off + 4..off + 6].copy_from_slice(&rec_len.to_le_bytes());
        if has_filetype {
            buf[off + 6] = name.len() as u8;
            buf[off + 7] = file_type;
        } else {
            buf[off + 6..off + 8].copy_from_slice(&(name.len() as u16).to_le_bytes());
        }
        buf[off + 8..off + 8 + name.len()].copy_from_slice(name);
    }

    #[test]
    fn parse_single_entry_with_filetype() {
        let mut buf = [0u8; 64];
        write_entry(&mut buf, 0, 42, 32, b"test.txt", 1, true);
        let info = parse_next_entry(&buf, 0, true, 2)
            .unwrap()
            .expect("should find entry");
        assert_eq!(info.inode, 42);
        assert_eq!(&buf[info.name_start..info.name_end], b"test.txt");
        assert_eq!(info.file_type, 1);
        assert_eq!(info.next_offset, 32);
    }

    #[test]
    fn parse_single_entry_without_filetype() {
        let mut buf = [0u8; 64];
        write_entry(&mut buf, 0, 42, 32, b"test.txt", 0, false);
        let info = parse_next_entry(&buf, 0, false, 2)
            .unwrap()
            .expect("should find entry");
        assert_eq!(info.inode, 42);
        assert_eq!(info.file_type, 0);
    }

    #[test]
    fn skips_dot_entries() {
        let mut buf = [0u8; 128];
        // "." at offset 0, rec_len=12 (8+1 name, padded to 12)
        write_entry(&mut buf, 0, 2, 12, b".", 2, true);
        // ".." at offset 12, rec_len=12
        write_entry(&mut buf, 12, 2, 12, b"..", 2, true);
        // "file" at offset 24
        write_entry(&mut buf, 24, 5, 16, b"file", 1, true);

        let info = parse_next_entry(&buf, 0, true, 2)
            .unwrap()
            .expect("should skip dots and find file");
        assert_eq!(info.inode, 5);
        assert_eq!(&buf[info.name_start..info.name_end], b"file");
    }

    #[test]
    fn skips_deleted_entries() {
        let mut buf = [0u8; 64];
        // Deleted entry (inode=0) at offset 0
        write_entry(&mut buf, 0, 0, 32, b"deleted", 1, true);
        // Valid entry at offset 32
        write_entry(&mut buf, 32, 10, 24, b"alive", 1, true);

        let info = parse_next_entry(&buf, 0, true, 2)
            .unwrap()
            .expect("should skip deleted entry");
        assert_eq!(info.inode, 10);
    }

    #[test]
    fn returns_none_at_end() {
        let buf = [0u8; 8];
        let result = parse_next_entry(&buf, 8, true, 2).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn rejects_bad_rec_len() {
        let mut buf = [0u8; 32];
        // rec_len = 3 (not aligned to 4 and < 8)
        write_entry(&mut buf, 0, 1, 3, b"x", 1, true);
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        let err = parse_next_entry(&buf, 0, true, 2).unwrap_err();
        assert!(
            matches!(err, ExtError::InvalidDirectoryEntry { .. }),
            "expected InvalidDirectoryEntry, got {err:?}"
        );
    }

    #[test]
    fn rejects_name_len_exceeding_rec_len() {
        let mut buf = [0u8; 32];
        // rec_len = 12, but name_len = 10 (max is 12-8=4)
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // inode
        buf[4..6].copy_from_slice(&12u16.to_le_bytes()); // rec_len
        buf[6] = 10; // name_len
        buf[7] = 1; // file_type
        let err = parse_next_entry(&buf, 0, true, 2).unwrap_err();
        assert!(
            matches!(err, ExtError::InvalidDirectoryEntry { .. }),
            "expected InvalidDirectoryEntry, got {err:?}"
        );
    }
}
