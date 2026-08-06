//! Crate-internal test helpers. Used by unit tests that need fixture access
//! or directory-traversal utilities. Not part of the public API.
#![cfg(test)]

use alloc::vec::Vec;

use crate::ext::Ext;
use crate::io::{Read, Seek};

pub(crate) fn load_clean_ext4_image() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    std::fs::read(&path).expect("read ext4.img fixture")
}

pub(crate) fn fixture_available(name: &str) -> bool {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
        .exists()
}

pub(crate) fn load_image(name: &str) -> fsmnt_testkit::Cursor<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    fsmnt_testkit::Cursor::new(std::fs::read(&path).expect("fixture"))
}

/// Resolve a single path component under the root directory and return its
/// lookup entry. Only supports flat `/name` lookups (no nested paths).
pub(crate) fn lookup_entry<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    path: &str,
) -> crate::error::Result<crate::traverse::ExtLookupEntry> {
    let name_bytes = path.trim_start_matches('/').as_bytes();
    let mut root = ext.root_directory();
    root.lookup(fs, name_bytes)
}
