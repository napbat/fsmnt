//! Integration tests for ext extended-attribute parsing and validation.

mod support;

/// Look up a root-level entry by name and return its inode number.
fn lookup_inode(ext: &fs_ext::Ext, fs: &mut std::io::Cursor<Vec<u8>>, name: &[u8]) -> u32 {
    let mut dir = ext.root_directory();
    let entry = dir.lookup(fs, name).unwrap();
    entry.inode_number
}

#[test]
fn ibody_xattrs_found() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"xattr_ibody");
    let inode = ext.inode(&mut fs, ino).unwrap();
    let xattrs = inode.xattrs(&mut fs).unwrap();

    let names: Vec<&str> = xattrs.iter().map(fs_ext::Xattr::name).collect();
    assert!(
        names.contains(&"user.greeting"),
        "expected user.greeting in {names:?}",
    );
    assert!(
        names.contains(&"user.tag"),
        "expected user.tag in {names:?}",
    );
    assert!(
        names.contains(&"security.selinux"),
        "expected security.selinux in {names:?}",
    );
}

#[test]
fn ibody_xattr_get_by_name() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"xattr_ibody");
    let inode = ext.inode(&mut fs, ino).unwrap();

    let val = inode.xattr(&mut fs, "user.greeting").unwrap();
    assert_eq!(val.as_deref(), Some(b"hello".as_slice()));

    let val = inode.xattr(&mut fs, "security.selinux").unwrap();
    assert_eq!(val.as_deref(), Some(b"unconfined_t".as_slice()));

    let val = inode.xattr(&mut fs, "user.nonexistent").unwrap();
    assert!(val.is_none());
}

#[test]
fn xattrs_on_file_without_xattrs() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"hello.txt");
    let inode = ext.inode(&mut fs, ino).unwrap();
    let xattrs = inode.xattrs(&mut fs).unwrap();
    // hello.txt was created without xattrs — should not error
    let _ = xattrs;
}

#[test]
fn block_xattr_file_has_entries() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"xattr_block");
    let inode = ext.inode(&mut fs, ino).unwrap();
    let xattrs = inode.xattrs(&mut fs).unwrap();

    // Should have multiple user.* xattrs
    let user_count = xattrs
        .iter()
        .filter(|x| x.name().starts_with("user."))
        .count();
    assert!(
        user_count >= 5,
        "expected at least 5 user.* xattrs, got {user_count}",
    );

    // Verify a known value was round-tripped exactly.
    let val = inode.xattr(&mut fs, "user.attr1").unwrap().unwrap();
    let expected = format!("{:060}", 1).into_bytes();
    assert_eq!(val, expected, "unexpected value for user.attr1");
}

#[test]
fn ea_inode_xattr_by_name() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"ea_inode_file");
    let inode = ext.inode(&mut fs, ino).unwrap();

    let val = inode.xattr(&mut fs, "user.big_value").unwrap().unwrap();
    // debugfs stored 4096 bytes of 'X'
    assert_eq!(val.len(), 4096);
    assert!(val.iter().all(|&b| b == b'X'), "value should be all 'X'");
}

#[test]
fn ea_inode_xattr_in_list() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"ea_inode_file");
    let inode = ext.inode(&mut fs, ino).unwrap();

    let xattrs = inode.xattrs(&mut fs).unwrap();
    let big = xattrs.iter().find(|x| x.name() == "user.big_value");
    assert!(big.is_some(), "user.big_value should be in xattr list");
    let big = big.unwrap();
    assert!(
        big.ea_inode().is_some(),
        "user.big_value should be stored in an EA inode",
    );
    assert_eq!(big.value().len(), 4096);
    assert!(
        big.value().iter().all(|&b| b == b'X'),
        "resolved EA inode value should be all 'X'",
    );
}

#[test]
fn ea_inode_nonexistent_xattr() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"ea_inode_file");
    let inode = ext.inode(&mut fs, ino).unwrap();

    let val = inode.xattr(&mut fs, "user.nonexistent").unwrap();
    assert!(val.is_none());
}
