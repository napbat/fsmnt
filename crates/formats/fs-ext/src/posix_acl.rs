//! Decoder for the Linux on-disk POSIX ACL xattr format.
//!
//! Linux stores POSIX ACLs in `system.posix_acl_access` and
//! `system.posix_acl_default` extended attributes using the
//! `posix_acl_xattr_header` + `posix_acl_xattr_entry[]` layout defined in
//! `<linux/posix_acl_xattr.h>`. This module decodes that blob into typed
//! [`PosixAclEntry`] values without performing semantic validation (e.g.
//! requiring `USER_OBJ`/`GROUP_OBJ`/`OTHER` to be present): consumers that
//! need kernel-grade validation should layer it on top.

use alloc::vec::Vec;

use crate::error::{ExtError, Result};

const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const POSIX_ACL_HEADER_SIZE: usize = 4;
const POSIX_ACL_ENTRY_SIZE: usize = 8;

const ACL_USER_OBJ: u16 = 0x0001;
const ACL_USER: u16 = 0x0002;
const ACL_GROUP_OBJ: u16 = 0x0004;
const ACL_GROUP: u16 = 0x0008;
const ACL_MASK: u16 = 0x0010;
const ACL_OTHER: u16 = 0x0020;

/// A decoded POSIX ACL entry from a Linux `system.posix_acl_*` xattr.
///
/// `perm` is the raw 16-bit permission word as stored on disk. POSIX defines
/// only the low three bits (`r=4`, `w=2`, `x=1`); higher bits are passed
/// through unmodified so callers can distinguish a kernel-written ACL from a
/// corrupted or hand-crafted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosixAclEntry {
    /// `ACL_USER_OBJ`: permissions of the file's owning user.
    UserObj { perm: u16 },
    /// `ACL_USER`: permissions for a named user identified by `uid`.
    User { uid: u32, perm: u16 },
    /// `ACL_GROUP_OBJ`: permissions of the file's owning group.
    GroupObj { perm: u16 },
    /// `ACL_GROUP`: permissions for a named group identified by `gid`.
    Group { gid: u32, perm: u16 },
    /// `ACL_MASK`: maximum effective permissions for `User`/`Group`/`GroupObj`.
    Mask { perm: u16 },
    /// `ACL_OTHER`: permissions for everyone else.
    Other { perm: u16 },
}

/// Decode a Linux on-disk `posix_acl_xattr_*` blob into typed entries.
///
/// `inode` is used purely for diagnostics — the bytes are decoded as a
/// standalone payload.
///
/// # Errors
///
/// Returns:
/// - [`ExtError::InvalidPosixAclLength`] if `bytes` is shorter than the
///   4-byte header or the trailing entry array is not a multiple of 8.
/// - [`ExtError::InvalidPosixAclVersion`] if the header version is not
///   `0x0002`.
/// - [`ExtError::InvalidPosixAclTag`] if an entry carries an unknown tag.
pub(crate) fn decode(inode: u32, bytes: &[u8]) -> Result<Vec<PosixAclEntry>> {
    let Some((header, rest)) = bytes.split_first_chunk::<POSIX_ACL_HEADER_SIZE>() else {
        return Err(ExtError::InvalidPosixAclLength {
            inode,
            offset: 0,
            len: bytes.len(),
        });
    };

    let version = u32::from_le_bytes(*header);
    if version != POSIX_ACL_XATTR_VERSION {
        return Err(ExtError::InvalidPosixAclVersion {
            inode,
            offset: 0,
            version,
        });
    }

    let chunks = rest.chunks_exact(POSIX_ACL_ENTRY_SIZE);
    if !chunks.remainder().is_empty() {
        // Misaligned trailing bytes: report the offset where the truncated
        // entry begins, relative to the start of the buffer.
        let truncated_start =
            POSIX_ACL_HEADER_SIZE + (rest.len() / POSIX_ACL_ENTRY_SIZE) * POSIX_ACL_ENTRY_SIZE;
        return Err(ExtError::InvalidPosixAclLength {
            inode,
            offset: truncated_start as u64,
            len: bytes.len(),
        });
    }

    let mut out = Vec::with_capacity(rest.len() / POSIX_ACL_ENTRY_SIZE);
    for (index, chunk) in chunks.enumerate() {
        let entry_offset = POSIX_ACL_HEADER_SIZE + index * POSIX_ACL_ENTRY_SIZE;
        // `chunks_exact(8)` guarantees `chunk.len() == 8`; reborrow as a fixed
        // array so the field reads compile to direct loads with no bounds
        // checks and no panic surface.
        let raw: &[u8; POSIX_ACL_ENTRY_SIZE] = chunk.try_into().unwrap_or(&[0; 8]);
        let tag = u16::from_le_bytes([raw[0], raw[1]]);
        let perm = u16::from_le_bytes([raw[2], raw[3]]);
        let id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

        let entry = match tag {
            ACL_USER_OBJ => PosixAclEntry::UserObj { perm },
            ACL_USER => PosixAclEntry::User { uid: id, perm },
            ACL_GROUP_OBJ => PosixAclEntry::GroupObj { perm },
            ACL_GROUP => PosixAclEntry::Group { gid: id, perm },
            ACL_MASK => PosixAclEntry::Mask { perm },
            ACL_OTHER => PosixAclEntry::Other { perm },
            unknown => {
                return Err(ExtError::InvalidPosixAclTag {
                    inode,
                    offset: entry_offset as u64,
                    tag: unknown,
                });
            }
        };

        out.push(entry);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use fs_common::error::FsError;

    use super::*;

    fn push_acl_entry(buf: &mut Vec<u8>, tag: u16, perm: u16, id: u32) {
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(&perm.to_le_bytes());
        buf.extend_from_slice(&id.to_le_bytes());
    }

    #[test]
    fn decodes_expected_acl_entries() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        push_acl_entry(&mut blob, ACL_USER_OBJ, 0o7, u32::MAX);
        push_acl_entry(&mut blob, ACL_USER, 0o7, 1000);
        push_acl_entry(&mut blob, ACL_GROUP_OBJ, 0o5, u32::MAX);
        push_acl_entry(&mut blob, ACL_MASK, 0o7, u32::MAX);
        push_acl_entry(&mut blob, ACL_OTHER, 0o0, u32::MAX);

        let entries = decode(42, &blob).unwrap();
        assert_eq!(
            entries,
            vec![
                PosixAclEntry::UserObj { perm: 0o7 },
                PosixAclEntry::User {
                    uid: 1000,
                    perm: 0o7,
                },
                PosixAclEntry::GroupObj { perm: 0o5 },
                PosixAclEntry::Mask { perm: 0o7 },
                PosixAclEntry::Other { perm: 0o0 },
            ]
        );
    }

    #[test]
    fn decodes_header_only_blob_as_empty() {
        // A 4-byte header with no entries is structurally valid even though
        // a kernel-written ACL always carries USER_OBJ/GROUP_OBJ/OTHER. The
        // decoder is intentionally permissive; semantic validation is the
        // caller's responsibility.
        let blob = POSIX_ACL_XATTR_VERSION.to_le_bytes();
        assert_eq!(decode(1, &blob).unwrap(), Vec::<PosixAclEntry>::new());
    }

    #[test]
    fn decodes_user_and_group_with_distinguishable_id_bytes() {
        // Locks little-endian byte order on the id field: a regression to
        // big-endian would read 0x04030201 instead of 0x01020304.
        let mut blob = Vec::new();
        blob.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        push_acl_entry(&mut blob, ACL_USER, 0o6, 0x01020304);
        push_acl_entry(&mut blob, ACL_GROUP, 0o4, 0x0A0B0C0D);

        let entries = decode(7, &blob).unwrap();
        assert_eq!(
            entries,
            vec![
                PosixAclEntry::User {
                    uid: 0x01020304,
                    perm: 0o6,
                },
                PosixAclEntry::Group {
                    gid: 0x0A0B0C0D,
                    perm: 0o4,
                },
            ]
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes());
        push_acl_entry(&mut blob, ACL_OTHER, 0o0, u32::MAX);

        let err = decode(77, &blob).unwrap_err();
        assert!(matches!(
            err,
            ExtError::InvalidPosixAclVersion {
                inode: 77,
                offset: 0,
                version: 1
            }
        ));
    }

    #[test]
    fn rejects_unknown_tag() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        push_acl_entry(&mut blob, 0x1234, 0o7, 1);

        let err = decode(123, &blob).unwrap_err();
        assert!(matches!(
            err,
            ExtError::InvalidPosixAclTag {
                inode: 123,
                offset: 4,
                tag: 0x1234
            }
        ));
    }

    #[test]
    fn rejects_truncated_trailing_entry() {
        // Header (version=2) + 1 stray byte: misaligned trailing bytes.
        let blob = [0x02, 0x00, 0x00, 0x00, 0xFF];
        let err = decode(88, &blob).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidPosixAclLength {
                    inode: 88,
                    offset: 4,
                    len: 5,
                }
            ),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn rejects_empty_input() {
        let err = decode(9, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidPosixAclLength {
                    inode: 9,
                    offset: 0,
                    len: 0,
                }
            ),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn rejects_truncated_header() {
        let err = decode(11, &[0x02, 0x00]).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidPosixAclLength {
                    inode: 11,
                    offset: 0,
                    len: 2,
                }
            ),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn new_error_variants_do_not_expose_relative_offsets_as_byte_offset() {
        // The `offset` fields on these variants are buffer-relative
        // diagnostics, not absolute disk offsets. They must NOT surface
        // through `FsError::byte_offset`, which is documented as the
        // offset within the disk image.
        let len_err = ExtError::InvalidPosixAclLength {
            inode: 1,
            offset: 4,
            len: 5,
        };
        let version_err = ExtError::InvalidPosixAclVersion {
            inode: 1,
            offset: 0,
            version: 1,
        };
        let tag_err = ExtError::InvalidPosixAclTag {
            inode: 1,
            offset: 4,
            tag: 0xABCD,
        };
        assert_eq!(FsError::byte_offset(&len_err), None);
        assert_eq!(FsError::byte_offset(&version_err), None);
        assert_eq!(FsError::byte_offset(&tag_err), None);
    }
}
