//! Crate-specific helpers shared by fs-ext integration-test targets.

use std::io::Cursor;

#[must_use]
pub(crate) fn load_image(name: &str) -> Cursor<Vec<u8>> {
    let data = fsmnt_testkit::read_required_fixture(
        env!("CARGO_MANIFEST_DIR"),
        format!("testdata/{name}"),
        "regenerate fixtures with `sudo bash crates/formats/fs-ext/testdata/gen-fixtures.sh`",
    );
    Cursor::new(data)
}

#[allow(dead_code, reason = "used by a subset of integration test binaries")]
#[must_use]
pub(crate) fn open_ext(name: &str) -> (fs_ext::Ext, Cursor<Vec<u8>>) {
    let mut fs = load_image(name);
    let ext = fs_ext::Ext::new(&mut fs).expect("failed to open ext filesystem");
    (ext, fs)
}

#[allow(dead_code, reason = "used by a subset of integration test binaries")]
pub(crate) fn patch_superblock_u16(fs: &mut Cursor<Vec<u8>>, offset: usize, value: u16) {
    let buf = fs.get_mut();
    buf[1024 + offset..1024 + offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[allow(dead_code, reason = "used by a subset of integration test binaries")]
pub(crate) fn patch_superblock_u32(fs: &mut Cursor<Vec<u8>>, offset: usize, value: u32) {
    let buf = fs.get_mut();
    buf[1024 + offset..1024 + offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[allow(dead_code, reason = "used by a subset of integration test binaries")]
pub(crate) fn patch_superblock_incompat(fs: &mut Cursor<Vec<u8>>, bits_to_set: u32) {
    let buf = fs.get_mut();
    let current = u32::from_le_bytes(buf[1024 + 0x60..1024 + 0x64].try_into().unwrap());
    let new = current | bits_to_set;
    buf[1024 + 0x60..1024 + 0x64].copy_from_slice(&new.to_le_bytes());
}

#[allow(dead_code, reason = "used by a subset of integration test binaries")]
pub(crate) fn patch_superblock_ro_compat(fs: &mut Cursor<Vec<u8>>, bits_to_set: u32) {
    let buf = fs.get_mut();
    let current = u32::from_le_bytes(buf[1024 + 0x64..1024 + 0x68].try_into().unwrap());
    let new = current | bits_to_set;
    buf[1024 + 0x64..1024 + 0x68].copy_from_slice(&new.to_le_bytes());
}
