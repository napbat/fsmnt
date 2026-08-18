//! fscrypt for the ext adapter: registering the operator's master keys,
//! and walking the tree to find out which keys the volume is asking for.
//!
//! An fscrypt volume opens whether or not the keys are to hand, which is
//! exactly what makes it easy to misread: the tree, the sizes and the
//! timestamps are all there, so a mount with no keys looks like a mount
//! that worked while every encrypted name reads as base64 noise and every
//! encrypted file refuses to be read. The census below is the answer to
//! that — before the volume appears, it says which master keys this
//! filesystem is asking for, which of them were supplied, and where the
//! directories they cover are.
//!
//! Only the walk is ext-specific. Reading a policy, naming its ciphers and
//! wording the notices belong to [`crate::fscrypt`], which any other
//! fscrypt-capable adapter (f2fs, UBIFS) shares.

use std::collections::VecDeque;

use fs_ext::io::{Read, Seek};
use fs_ext::{Ext, ExtError, FscryptKeyDescriptor, FscryptMasterKey, FscryptPolicy};
use fsmnt_core::{FsError, FsResult};
use fsmnt_device::FscryptKeySpec;
use fsmnt_parser_core::iter::FsTryIterator;
use tracing::debug;

use crate::fscrypt::{
    CENSUS_MAX_DEPTH, CENSUS_MAX_DIRECTORIES, KeyCensus, child_path, hex, key_reference,
};

use super::{EXT4_ROOT_INO, Reader};

/// Register each supplied master key with the opened filesystem.
///
/// The keys are numbered as the caller gave them, because that is how an
/// operator can find the one that was wrong: nothing else about a key is
/// safe to put in an error message.
///
/// # Errors
///
/// Returns an error when a key is not a length fscrypt accepts, or when a
/// v1 key is too short for v1 key derivation.
pub(super) fn register_keys(ext: &mut Ext, specs: &[FscryptKeySpec]) -> FsResult<()> {
    for (index, spec) in specs.iter().enumerate() {
        let position = index + 1;
        let key = FscryptMasterKey::from_bytes(spec.key())
            .map_err(|error| key_error(position, &error))?;
        if let Some(descriptor) = spec.descriptor() {
            ext.add_fscrypt_v1_key(FscryptKeyDescriptor(descriptor), key)
                .map_err(|error| key_error(position, &error))?;
            debug!(
                key = position,
                descriptor = %hex(&descriptor),
                key_bytes = spec.key().len(),
                "registered a v1 fscrypt master key"
            );
        } else {
            let identifier = ext.add_fscrypt_v2_key(key);
            debug!(
                key = position,
                identifier = %hex(&identifier.0),
                key_bytes = spec.key().len(),
                "registered a v2 fscrypt master key"
            );
        }
    }
    Ok(())
}

/// Name the key by position and say what was wrong with it.
///
/// `ExtError::InvalidFscryptPolicy` renders with an inode number, which is
/// zero here because no inode was involved — the reason alone is the part
/// that helps.
fn key_error(position: usize, error: &ExtError) -> FsError {
    let detail = match error {
        ExtError::InvalidFscryptPolicy { reason, .. } => (*reason).to_string(),
        other => other.to_string(),
    };
    FsError::Filesystem(format!("fscrypt key #{position}: {detail}"))
}

/// Everything the mount should say about this volume's encryption.
///
/// Never fails: a census that cannot read a directory says less, it does
/// not stop the volume from being mounted. Returns an empty list for a
/// filesystem that was not formatted for fscrypt, and for one that was but
/// carries no encrypted directory the walk could reach.
pub(super) fn notices<R: Read + Seek>(ext: &Ext, reader: &mut Reader<'_, R>) -> Vec<String> {
    if !ext.has_fscrypt() {
        return Vec::new();
    }
    let census = walk(ext, reader);
    if census.is_empty() {
        return Vec::new();
    }
    let registered = ext.fscrypt_v1_descriptors().count() + ext.fscrypt_v2_identifiers().count();
    census.into_notices(registered)
}

/// Walk the top of the tree collecting the distinct policies it carries.
///
/// Breadth-first, so the shallowest — and so most recognisable — paths are
/// the ones that end up as examples. An encrypted directory is recorded and
/// then *not* descended into: fscrypt policies are inherited, so everything
/// below it answers to the same key, and without that key its children's
/// names are ciphertext anyway.
fn walk<R: Read + Seek>(ext: &Ext, reader: &mut Reader<'_, R>) -> KeyCensus {
    let mut census = KeyCensus::default();
    let mut queue: VecDeque<(u32, String, usize)> =
        VecDeque::from([(EXT4_ROOT_INO, "/".to_string(), 0)]);
    let mut visited = 0usize;

    while let Some((inum, path, depth)) = queue.pop_front() {
        if visited >= CENSUS_MAX_DIRECTORIES {
            debug!(
                limit = CENSUS_MAX_DIRECTORIES,
                "fscrypt key census stopped at its directory limit"
            );
            break;
        }
        visited += 1;

        let inode = match ext.inode(reader, inum) {
            Ok(inode) => inode,
            Err(error) => {
                debug!(inode = inum, %path, %error, "fscrypt census skipped an unreadable inode");
                continue;
            }
        };
        if !inode.is_directory() {
            continue;
        }
        let policy = match inode.fscrypt_policy(reader) {
            Ok(policy) => policy,
            Err(error) => {
                debug!(inode = inum, %path, %error, "fscrypt census could not read a policy");
                continue;
            }
        };
        if let Some(policy) = policy {
            let (_, key_ref) = key_reference(&policy);
            debug!(inode = inum, %path, %key_ref, "fscrypt census found a policy");
            census.record(
                &policy,
                inode.is_casefolded(),
                key_registered(ext, &policy),
                path,
            );
            // Inherited below here: descending finds the same key.
            continue;
        }
        if depth == CENSUS_MAX_DEPTH {
            continue;
        }
        for (name, child) in child_directories(ext, reader, inum, &path) {
            queue.push_back((child, child_path(&path, &name), depth + 1));
        }
    }
    census
}

/// The child directories of `inum`, as `(name, inode)`.
///
/// Only reached for unencrypted directories, so the names are plaintext.
/// Every failure is a reason to report less, never to fail the mount.
fn child_directories<R: Read + Seek>(
    ext: &Ext,
    reader: &mut Reader<'_, R>,
    inum: u32,
    path: &str,
) -> Vec<(String, u32)> {
    /// `EXT4_FT_DIR`, the dirent type byte for a directory.
    const EXT4_FT_DIR: u8 = 2;
    /// The type byte every entry carries on a filesystem without the
    /// FILETYPE feature (ext2, and ext3 as originally formatted).
    const EXT4_FT_UNKNOWN: u8 = 0;

    let mut raw: Vec<(String, u32, u8)> = Vec::new();
    {
        let mut dir = ext.directory_at(inum);
        let mut iter = match dir.raw_entries(reader) {
            Ok(iter) => iter,
            Err(error) => {
                debug!(inode = inum, %path, %error, "fscrypt census could not list a directory");
                return Vec::new();
            }
        };
        loop {
            match iter.try_next(reader) {
                Ok(Some(entry)) => {
                    let name = entry.name_bytes();
                    if name == b"." || name == b".." {
                        continue;
                    }
                    raw.push((
                        String::from_utf8_lossy(name).into_owned(),
                        entry.inode_number(),
                        entry.file_type(),
                    ));
                }
                Ok(None) => break,
                Err(error) => {
                    debug!(inode = inum, %path, %error, "fscrypt census stopped mid-listing");
                    break;
                }
            }
        }
    }

    raw.into_iter()
        .filter_map(|(name, child, file_type)| match file_type {
            EXT4_FT_DIR => Some((name, child)),
            // Without FILETYPE the byte is always zero, so the child inode
            // is the only way to know. One read per entry, and only on the
            // filesystems that have no other answer.
            EXT4_FT_UNKNOWN => ext
                .inode(reader, child)
                .is_ok_and(|inode| inode.is_directory())
                .then_some((name, child)),
            _ => None,
        })
        .collect()
}

/// Whether one of the registered keys covers this policy.
fn key_registered(ext: &Ext, policy: &FscryptPolicy) -> bool {
    if let Some(descriptor) = policy.key_descriptor {
        return ext
            .fscrypt_v1_descriptors()
            .any(|registered| registered.0 == descriptor.0);
    }
    if let Some(identifier) = policy.key_identifier {
        return ext
            .fscrypt_v2_identifiers()
            .any(|registered| registered.0 == identifier.0);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_that_cannot_be_registered_is_named_by_position() {
        let error = key_error(
            2,
            &ExtError::InvalidFscryptPolicy {
                inode: 0,
                reason: "v1 master keys must be at least 64 bytes for AES-256-XTS",
            },
        );
        let message = error.to_string();
        assert!(message.contains("fscrypt key #2"), "{message}");
        assert!(
            message.contains("v1 master keys must be at least 64 bytes"),
            "{message}"
        );
        // The inode-0 framing of the parser error is noise here.
        assert!(!message.contains("inode 0"), "{message}");
    }
}
