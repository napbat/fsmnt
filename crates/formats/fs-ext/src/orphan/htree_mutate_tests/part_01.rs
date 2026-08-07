use super::*;
use crate::checksum::ChecksumState;
use fsmnt_parser_core::FsTryIterator;

/// Inode of the 500-file htree directory `/htree_dir` in ext4.img.
const HTREE_DIR: u32 = 21;

/// Build a `(Ext, image_bytes)` pair from the htree fixture.
fn fixture() -> (Ext, Vec<u8>) {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes.clone());
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    (ext, bytes)
}

/// Read the sb-host block for `Mutator::new`.
fn sb_host_block(ext: &Ext, image: &[u8]) -> alloc::boxed::Box<[u8]> {
    let bs = ext.block_size() as usize;
    let host = usize::from(ext.block_size() <= 1024);
    image[host * bs..host * bs + bs].to_vec().into_boxed_slice()
}

/// Apply a finalized `OrphanOverlayDelta` onto a fresh copy of the
/// image, then re-open it so post-replay lookups see the new state.
fn apply_delta(
    ext: &Ext,
    image: &[u8],
    delta: &crate::orphan::plan::OrphanOverlayDelta,
) -> Vec<u8> {
    let bs = ext.block_size() as usize;
    let mut out = image.to_vec();
    for (&block, content) in &delta.blocks {
        let start = usize::try_from(block).expect("the test fixture value fits in usize") * bs;
        out[start..start + content.len()].copy_from_slice(content);
    }
    if let Some(sb_host) = &delta.sb_host_override {
        out[0..sb_host.len()].copy_from_slice(sb_host);
    }
    out
}

/// Pick a fresh entry name of `len` bytes whose half-MD4 hash routes
/// to `dx_entry` index `want_index` of the `/htree_dir` `dx_root`. A long
/// `len` is used to force a leaf split; a short `len` to land in a
/// leaf with room.
fn name_for_leaf(ext: &Ext, image: &[u8], want_index: usize, len: usize) -> Vec<u8> {
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
    let i_block = dir.i_block();
    let root_pblk = crate::extent::resolve_extent(
        ext,
        &mut cursor,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        0,
    )
    .expect("resolve dx_root")
    .expect("dx_root extent")
    .physical_block;
    let bs = ext.block_size() as usize;
    let root = &image[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    let header = parse_dx_root(root, HTREE_DIR).expect("parse dx_root");

    for n in 0..1_000_000u32 {
        let mut name = alloc::format!("zfc{n:09}").into_bytes();
        name.resize(len, b'x');
        let hash = dx_hash(&name, header.hash_version, ext.hash_seed())
            .expect("hash")
            .major;
        let (idx, _) =
            choose_child(root, DX_ROOT_COUNT_LIMIT_OFFSET, hash, HTREE_DIR).expect("choose");
        if idx == want_index {
            return name;
        }
    }
    panic!("no probe name routed to dx_entry {want_index}");
}

/// Collect `n` distinct long names that all route to `dx_entry` index
/// `want_index` of the original `dx_root`. Inserting them in order
/// fills the target leaf and forces a split.
fn names_for_leaf(ext: &Ext, image: &[u8], want_index: usize, n: usize) -> Vec<Vec<u8>> {
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
    let i_block = dir.i_block();
    let root_pblk = crate::extent::resolve_extent(
        ext,
        &mut cursor,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        0,
    )
    .expect("resolve dx_root")
    .expect("dx_root extent")
    .physical_block;
    let bs = ext.block_size() as usize;
    let root = &image[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    let header = parse_dx_root(root, HTREE_DIR).expect("parse dx_root");

    let mut out = Vec::new();
    for seq in 0..1_000_000u32 {
        // 250-byte names: only ~3 fit a leaf's free slack, so the
        // fourth forces a split.
        let mut name = alloc::format!("zsplit{seq:09}").into_bytes();
        name.resize(250, b'q');
        let hash = dx_hash(&name, header.hash_version, ext.hash_seed())
            .expect("hash")
            .major;
        let (idx, _) =
            choose_child(root, DX_ROOT_COUNT_LIMIT_OFFSET, hash, HTREE_DIR).expect("choose");
        if idx == want_index {
            out.push(name);
            if out.len() == n {
                return out;
            }
        }
    }
    panic!("could not collect {n} names for dx_entry {want_index}");
}

/// Verify both htree and sequential lookup agree on `name` in
/// `/htree_dir`, and that every dx node and dir leaf checksum is
/// valid. `expect` is `Some(inode)` when the name must be present.
fn assert_consistent(image: &[u8], name: &[u8], expect: Option<u32>) {
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let ext = Ext::open_lenient(&mut cursor).expect("re-open image");
    let mut dir = ext.directory_at(HTREE_DIR);
    let htree = dir.lookup(&mut cursor, name);
    match expect {
        Some(inode) => {
            let entry = htree.expect("htree lookup must find the name");
            assert_eq!(entry.inode_number, inode, "htree lookup inode mismatch");
        }
        None => {
            assert!(
                matches!(htree, Err(crate::error::ExtError::NotFound)),
                "htree lookup must miss a removed name"
            );
        }
    }
    // Sequential scan must agree with the htree result.
    let seq = sequential_find(&ext, &mut cursor, name);
    assert_eq!(seq, expect, "sequential scan disagrees with htree lookup");
    assert_dx_and_leaf_checksums(&ext, image);
}

/// Sequential directory scan: returns the inode for `name`, or `None`.
fn sequential_find(
    ext: &Ext,
    cursor: &mut fsmnt_testkit::Cursor<Vec<u8>>,
    name: &[u8],
) -> Option<u32> {
    let mut dir = ext.directory_at(HTREE_DIR);
    let mut iter = dir.raw_entries(cursor).expect("raw entries");
    while let Some(entry) = iter.try_next(cursor).expect("raw entry") {
        if entry.name_bytes() == name {
            return Some(entry.inode_number());
        }
    }
    None
}

/// Walk every directory block of `/htree_dir`: `dx_root/dx_node` blocks
/// must pass `verify_dx_*`, leaf blocks must pass `verify_dir_block`.
fn assert_dx_and_leaf_checksums(ext: &Ext, image: &[u8]) {
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
    let seed = ext.checksum_seed().expect("metadata_csum fixture");
    let generation = dir.generation();
    let bs = ext.block_size() as usize;
    let dir_blocks = dir.size().div_ceil(bs as u64);
    let i_block = dir.i_block();

    let root_pblk =
        crate::extent::resolve_extent(ext, &mut cursor, HTREE_DIR, generation, &i_block, 0)
            .expect("resolve dx_root")
            .expect("dx_root extent")
            .physical_block;
    let root = &image[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    let count = u16::from_le_bytes([root[0x22], root[0x23]]);
    let limit = u16::from_le_bytes([root[0x20], root[0x21]]);
    assert_eq!(
        crate::checksum::verify_dx_root(seed, HTREE_DIR, generation, root, count, limit),
        ChecksumState::Valid,
        "dx_root checksum invalid post-replay"
    );

    for logical in 1..dir_blocks {
        let logical = u32::try_from(logical).expect("the test fixture value fits in u32");
        let pblk = crate::extent::resolve_extent(
            ext,
            &mut cursor,
            HTREE_DIR,
            generation,
            &i_block,
            logical,
        )
        .expect("resolve leaf")
        .expect("leaf extent")
        .physical_block;
        let block = &image[usize::try_from(pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(pblk).expect("the test fixture value fits in usize") * bs + bs];
        assert_eq!(
            crate::checksum::verify_dir_block(seed, HTREE_DIR, generation, block),
            ChecksumState::Valid,
            "dir leaf {logical} checksum invalid post-replay"
        );
    }
}

/// Run `body` against a fresh `HtreeSurgeon`, finalize, and return the
/// post-replay image bytes.
fn run_surgery<F>(ext: &Ext, image: &[u8], body: F) -> Vec<u8>
where
    F: FnOnce(&mut HtreeSurgeon<'_, '_, fsmnt_testkit::Cursor<Vec<u8>>>) -> DirReplayOutcome,
{
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let mut mutator = Mutator::new(ext, &sb_host_block(ext, image));
    let outcome = {
        let mut surgeon = HtreeSurgeon::new(ext, &mut cursor, &mut mutator);
        body(&mut surgeon)
    };
    assert_eq!(outcome, DirReplayOutcome::Applied, "surgery did not apply");
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    apply_delta(ext, image, &delta)
}

#[test]
fn creat_into_leaf_with_room_inserts_without_dx_change() {
    let (ext, image) = fixture();
    // dx_entry index 3 backs the near-empty fourth leaf (8 entries).
    let name = name_for_leaf(&ext, &image, 3, 16);
    let child = 23u32;

    let after = run_surgery(&ext, &image, |s| {
        s.add_entry(HTREE_DIR, child, &name, 1)
            .expect("creat into htree parent")
    });

    assert_consistent(&after, &name, Some(child));
    // dx_root count unchanged: leaf had room, no split.
    let mut cursor = fsmnt_testkit::Cursor::new(after.clone());
    let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
    assert!(reopened.has_dir_index());
}

#[test]
fn link_into_htree_parent_uses_creat_path() {
    let (ext, image) = fixture();
    let name = name_for_leaf(&ext, &image, 3, 16);
    let child = 24u32;
    // LINK and CREAT share the add_entry path; verify a second add.
    let after = run_surgery(&ext, &image, |s| {
        s.add_entry(HTREE_DIR, child, &name, 1)
            .expect("link into htree parent")
    });
    assert_consistent(&after, &name, Some(child));
}

/// Byte offset of inode `inum`'s on-disk `i_flags` field in `image`.
fn inode_flags_offset(ext: &Ext, inum: u32) -> usize {
    let group = ((inum - 1) / ext.inodes_per_group) as usize;
    let index = u64::from((inum - 1) % ext.inodes_per_group);
    let table = ext.group_descs[group].inode_table;
    let bs = u64::from(ext.block_size());
    usize::try_from(table * bs + index * u64::from(ext.inode_size()) ).expect("the test fixture value fits in usize") + 0x20
}

#[test]
fn add_entry_skips_unsupported_htree_variant_without_aborting() {
    // An htree directory whose variant this maintainer does not
    // support (here: casefold) must yield SkippedHtree so the caller
    // emits a HtreeNotMaintained warning and preserves forward
    // progress — not a hard error that aborts the whole FC replay.
    let (ext, mut image) = fixture();
    let off = inode_flags_offset(&ext, HTREE_DIR);
    let mut flags = u32::from_le_bytes(image[off..off + 4].try_into().unwrap());
    flags |= InodeFlags::CASEFOLD_FL.bits();
    image[off..off + 4].copy_from_slice(&flags.to_le_bytes());

    let mut cursor = fsmnt_testkit::Cursor::new(image.clone());
    let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
    let outcome = {
        let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
        surgeon
            .add_entry(HTREE_DIR, 23, b"casefold-skip", 1)
            .expect("casefolded htree must skip, not error")
    };
    assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
}

#[test]
fn write_dir_entry_encodes_name_len_per_filetype_feature() {
    let entry = LeafEntry {
        inode: 42,
        file_type: 7,
        name: b"report.txt".to_vec(),
        order: 0,
        hash: 0,
    };

    // No `filetype` feature: bytes 6..8 are a single LE u16 name_len;
    // the file type must not bleed into byte 7.
    let mut no_ft = alloc::vec![0u8; 64];
    write_dir_entry(&mut no_ft, 0, &entry, 24, false);
    assert_eq!(
        u16::from_le_bytes([no_ft[6], no_ft[7]]),
        u16::try_from(entry.name.len()).expect("the test fixture value fits in u16"),
    );
    assert_eq!(
        no_ft[7], 0,
        "file type must not corrupt the name_len high byte"
    );

    // With `filetype`: byte 6 = u8 name_len, byte 7 = file type.
    let mut ft = alloc::vec![0u8; 64];
    write_dir_entry(&mut ft, 0, &entry, 24, true);
    assert_eq!(ft[6], (entry.name.len()).to_le_bytes()[0]);
    assert_eq!(ft[7], 7);
}

#[test]
fn creat_forcing_leaf_split_redistributes_and_updates_dx() {
    let (ext, image) = fixture();
    // Four long names into the same leaf: the fourth overflows the
    // leaf's free slack and forces a split.
    let names = names_for_leaf(&ext, &image, 1, 4);
    let child = 25u32;

    let after = run_surgery(&ext, &image, |s| {
        let mut last = DirReplayOutcome::Applied;
        for name in &names {
            last = s
                .add_entry(HTREE_DIR, child, name, 1)
                .expect("creat forcing leaf split");
        }
        last
    });

    // Every inserted name is reachable and both lookup paths agree.
    for name in &names {
        assert_consistent(&after, name, Some(child));
    }

    // The directory grew by one logical block and the dx_root gained
    // a dx_entry (count 4 -> 5).
    let mut cursor = fsmnt_testkit::Cursor::new(after.clone());
    let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
    let dir = reopened.inode(&mut cursor, HTREE_DIR).expect("inode");
    assert_eq!(dir.size(), 6 * u64::from(ext.block_size()), "i_size grew");

    let i_block = dir.i_block();
    let root_pblk = crate::extent::resolve_extent(
        &reopened,
        &mut cursor,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        0,
    )
    .expect("resolve")
    .expect("extent")
    .physical_block;
    let bs = ext.block_size() as usize;
    let root = &after[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    let count = u16::from_le_bytes([root[0x22], root[0x23]]);
    assert_eq!(count, 5, "dx_root gained a dx_entry after the split");
}

#[test]
fn split_keeps_every_preexisting_name_reachable() {
    let (ext, image) = fixture();
    let names = names_for_leaf(&ext, &image, 2, 4);
    let child = 26u32;
    let after = run_surgery(&ext, &image, |s| {
        let mut last = DirReplayOutcome::Applied;
        for name in &names {
            last = s
                .add_entry(HTREE_DIR, child, name, 1)
                .expect("creat forcing split");
        }
        last
    });
    // The split moved entries into a freshly appended block.
    let mut cursor = fsmnt_testkit::Cursor::new(after.clone());
    let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
    assert_eq!(
        reopened.inode(&mut cursor, HTREE_DIR).unwrap().size(),
        6 * u64::from(ext.block_size()),
        "split must append one directory block"
    );

    // Every original file_NNN.txt (the fixture names file_001.txt
    // through file_500.txt) resolves through the htree and the
    // sequential scan identically, in whichever post-split block.
    let mut found = 0u32;
    for n in 1..=500u32 {
        let fname = alloc::format!("file_{n:03}.txt");
        let seq = sequential_find(&reopened, &mut cursor, fname.as_bytes());
        let mut dir = reopened.directory_at(HTREE_DIR);
        let htree = dir.lookup(&mut cursor, fname.as_bytes());
        match seq {
            Some(inode) => {
                let entry =
                    htree.unwrap_or_else(|_| panic!("htree must find surviving name {fname}"));
                assert_eq!(entry.inode_number, inode, "lookup mismatch {fname}");
                found += 1;
            }
            None => assert!(
                matches!(htree, Err(crate::error::ExtError::NotFound)),
                "htree found {fname} that sequential scan did not"
            ),
        }
    }
    assert_eq!(found, 500, "all 500 fixture files must survive the split");
    for name in &names {
        assert_consistent(&after, name, Some(child));
    }
}

#[test]
fn unlink_from_htree_parent_removes_entry() {
    let (ext, image) = fixture();
    // file_002.txt is inode 23 per the fixture (debugfs ls).
    let name = b"file_002.txt";
    let after = run_surgery(&ext, &image, |s| {
        s.remove_entry(HTREE_DIR, 23, name)
            .expect("unlink from htree parent")
    });
    assert_consistent(&after, name, None);
}

#[test]
fn unlink_missing_name_reports_target_missing() {
    let (ext, image) = fixture();
    let mut cursor = fsmnt_testkit::Cursor::new(image.clone());
    let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
    let outcome = {
        let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
        surgeon
            .remove_entry(HTREE_DIR, 999, b"no_such_name.txt")
            .expect("unlink missing")
    };
    assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);
}

#[test]
fn unlink_emptying_leaf_prunes_dx_entry() {
    // The fourth leaf (dx_entry 3) holds only 8 entries; remove all of
    // them so the leaf empties and its dx_entry is pruned.
    let (ext, image) = fixture();
    let mut cursor = fsmnt_testkit::Cursor::new(image.clone());
    let names = leaf_three_entry_names(&ext, &image);
    assert!(!names.is_empty(), "fourth leaf must hold entries");

    let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
    {
        let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
        for (inode, name) in &names {
            let outcome = surgeon
                .remove_entry(HTREE_DIR, *inode, name)
                .expect("unlink leaf entry");
            assert_eq!(outcome, DirReplayOutcome::Applied);
        }
    }
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let after = apply_delta(&ext, &image, &delta);

    // dx_root lost the now-empty leaf's dx_entry (count 4 -> 3).
    let bs = ext.block_size() as usize;
    let mut rc = fsmnt_testkit::Cursor::new(after.clone());
    let reopened = Ext::open_lenient(&mut rc).expect("reopen");
    let dir = reopened.inode(&mut rc, HTREE_DIR).expect("inode");
    let i_block = dir.i_block();
    let root_pblk = crate::extent::resolve_extent(
        &reopened,
        &mut rc,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        0,
    )
    .expect("resolve")
    .expect("extent")
    .physical_block;
    let root = &after[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    let count = u16::from_le_bytes([root[0x22], root[0x23]]);
    assert_eq!(count, 3, "emptied leaf's dx_entry must be pruned");
    assert_dx_and_leaf_checksums(&ext, &after);
}

/// Collect `(inode, name)` for every entry in the fourth dx leaf
/// (`dx_entry` index 3) of `/htree_dir`.
fn leaf_three_entry_names(ext: &Ext, image: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut cursor = fsmnt_testkit::Cursor::new(image.to_vec());
    let dir = ext.inode(&mut cursor, HTREE_DIR).expect("inode");
    let i_block = dir.i_block();
    let bs = ext.block_size() as usize;
    let root_pblk = crate::extent::resolve_extent(
        ext,
        &mut cursor,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        0,
    )
    .expect("resolve")
    .expect("extent")
    .physical_block;
    let root = &image[usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(root_pblk).expect("the test fixture value fits in usize") * bs + bs];
    // dx_entry index 3 -> child logical block.
    let off = DX_ROOT_COUNT_LIMIT_OFFSET + 3 * DX_ENTRY_SIZE;
    let leaf_logical = u32::from_le_bytes(root[off + 4..off + 8].try_into().unwrap());
    let leaf_pblk = crate::extent::resolve_extent(
        ext,
        &mut cursor,
        HTREE_DIR,
        dir.generation(),
        &i_block,
        leaf_logical,
    )
    .expect("resolve leaf")
    .expect("leaf extent")
    .physical_block;
    let leaf = &image[usize::try_from(leaf_pblk).expect("the test fixture value fits in usize") * bs..usize::try_from(leaf_pblk).expect("the test fixture value fits in usize") * bs + bs];
    collect_leaf_entries(leaf, ext.has_filetype(), HTREE_DIR)
        .expect("collect")
        .into_iter()
        .map(|e| (e.inode, e.name))
        .collect()
}
