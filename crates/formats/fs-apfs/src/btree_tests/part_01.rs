use super::*;
use fs_common::iter::FsTryIterator;
use fsmnt_testkit::Cursor;

const NODE_SIZE: usize = 4096;

/// Builds a fixed-kv node with `u64` keys and `value_len`-byte values.
///
/// `entries` are already sorted by key. When `root` is set, a
/// `btree_info_t` trailer is appended describing 8-byte keys and
/// `leaf_val_len`-byte leaf values.
fn build_node(
    level: u16,
    leaf: bool,
    root: bool,
    entries: &[(u64, Vec<u8>)],
    leaf_val_len: usize,
) -> Vec<u8> {
    let mut block = vec![0u8; NODE_SIZE];
    let mut flags = BtnodeFlags::FIXED_KV_SIZE;
    if leaf {
        flags |= BtnodeFlags::LEAF;
    }
    if root {
        flags |= BtnodeFlags::ROOT;
    }
    block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
    block[34..36].copy_from_slice(&level.to_le_bytes());
    block[36..40].copy_from_slice(&u32::try_from(entries.len()).expect("the test fixture value fits in u32").to_le_bytes());

    // Table of contents directly after the header (btn_table_space.off 0).
    let toc_len = entries.len() * 4;
    block[40..42].copy_from_slice(&0u16.to_le_bytes());
    block[42..44].copy_from_slice(&u16::try_from(toc_len).expect("the test fixture value fits in u16").to_le_bytes());

    let key_area = BTN_DATA_OFFSET + toc_len;
    let value_end = if root {
        NODE_SIZE - BTREE_INFO_SIZE
    } else {
        NODE_SIZE
    };
    let val_len = entries.first().map_or(0, |(_, v)| v.len());

    for (i, (key, value)) in entries.iter().enumerate() {
        let k_off = u16::try_from(i * 8).expect("the test fixture value fits in u16");
        let v_off = u16::try_from((i + 1) * value.len()).expect("the test fixture value fits in u16");
        let toc = BTN_DATA_OFFSET + i * 4;
        block[toc..toc + 2].copy_from_slice(&k_off.to_le_bytes());
        block[toc + 2..toc + 4].copy_from_slice(&v_off.to_le_bytes());

        let ks = key_area + i * 8;
        block[ks..ks + 8].copy_from_slice(&key.to_le_bytes());
        let vs = value_end - (i + 1) * value.len();
        block[vs..vs + value.len()].copy_from_slice(value);
    }

    if root {
        let info = NODE_SIZE - BTREE_INFO_SIZE;
        block[info..info + 4].copy_from_slice(&BtreeFlags::PHYSICAL.bits().to_le_bytes());
        block[info + 4..info + 8].copy_from_slice(&u32::try_from(NODE_SIZE).expect("the test fixture value fits in u32").to_le_bytes());
        block[info + 8..info + 12].copy_from_slice(&8u32.to_le_bytes());
        let stored_val = if leaf { leaf_val_len } else { val_len };
        block[info + 12..info + 16].copy_from_slice(&u32::try_from(stored_val).expect("the test fixture value fits in u32").to_le_bytes());
    }
    block
}

fn leaf_entries() -> Vec<(u64, Vec<u8>)> {
    vec![
        (10, vec![0xA0; 8]),
        (20, vec![0xA1; 8]),
        (30, vec![0xA2; 8]),
        (40, vec![0xA3; 8]),
    ]
}

fn cmp_u64(a: &[u8], b: &[u8]) -> Ordering {
    let av = u64::from_le_bytes(a[..8].try_into().unwrap());
    let bv = u64::from_le_bytes(b[..8].try_into().unwrap());
    av.cmp(&bv)
}

#[test]
fn parses_header_fields() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    assert!(node.is_leaf());
    assert!(node.is_root());
    assert_eq!(node.level(), 0);
    assert_eq!(node.key_count(), 4);
    assert!(node.flags().contains(BtnodeFlags::FIXED_KV_SIZE));
}

#[test]
fn rejects_a_block_smaller_than_the_header() {
    match BtreeNode::parse(vec![0u8; 16]) {
        Err(ApfsError::Truncated { structure, .. }) => {
            assert_eq!(structure, "btree_node_phys_t");
        }
        other => panic!("expected Truncated, got {other:?}"),
    }
}

#[test]
fn rejects_a_toc_past_the_node() {
    let mut block = build_node(0, true, true, &leaf_entries(), 8);
    // Push btn_table_space.len well past the end of the block.
    block[42..44].copy_from_slice(&0xFFFFu16.to_le_bytes());
    match BtreeNode::parse(block) {
        Err(ApfsError::Malformed { reason, .. }) => {
            assert_eq!(reason, "table of contents extends past the node");
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn entry_extracts_key_and_value() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    let entry = node.entry(2, 8, 8).unwrap();
    assert_eq!(u64::from_le_bytes(entry.key.try_into().unwrap()), 30);
    assert_eq!(entry.value.unwrap(), &[0xA2; 8]);
}

#[test]
fn entry_index_out_of_range_is_rejected() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    assert!(node.entry(4, 8, 8).is_err());
}

#[test]
fn btree_info_only_on_root() {
    let root = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    let info = root.btree_info().unwrap().unwrap();
    assert_eq!(info.key_size, 8);
    assert_eq!(info.val_size, 8);
    assert!(info.flags.contains(BtreeFlags::PHYSICAL));

    let nonroot = BtreeNode::parse(build_node(0, true, false, &leaf_entries(), 8)).unwrap();
    assert!(nonroot.btree_info().unwrap().is_none());
}

#[test]
fn node_entries_iterator_yields_every_pair() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    let mut reader = Cursor::new(Vec::new());
    let mut iter = node.entries(8, 8);
    let mut keys = Vec::new();
    while let Some(entry) = iter.try_next(&mut reader).unwrap() {
        keys.push(u64::from_le_bytes(entry.key.try_into().unwrap()));
    }
    assert_eq!(keys, vec![10, 20, 30, 40]);
}

#[test]
fn find_le_returns_the_predecessor() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    // Exact key present.
    let exact = node.find_le(&20u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
    assert_eq!(
        u64::from_le_bytes(exact.unwrap().key.try_into().unwrap()),
        20
    );
    // No exact key: the largest key below 25 is 20.
    let pred = node.find_le(&25u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
    assert_eq!(
        u64::from_le_bytes(pred.unwrap().key.try_into().unwrap()),
        20
    );
    // Search precedes every key.
    let missing = node.find_le(&5u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
    assert!(missing.is_none());
}

#[test]
fn find_equal_locates_and_misses() {
    let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
    let hit = node
        .find_equal(&30u64.to_le_bytes(), 8, 8, cmp_u64)
        .unwrap();
    assert_eq!(hit.unwrap().value.unwrap(), &[0xA2; 8]);
    let miss = node
        .find_equal(&25u64.to_le_bytes(), 8, 8, cmp_u64)
        .unwrap();
    assert!(miss.is_none());
}

#[test]
fn descend_two_levels_to_a_leaf() {
    // Two leaves; a root index node keyed by each leaf's smallest key.
    let left = leaf_entries();
    let right = vec![(50u64, vec![0xB0; 8]), (60, vec![0xB1; 8])];
    let leaf_left = build_node(0, true, false, &left, 8);
    let leaf_right = build_node(0, true, false, &right, 8);

    // Root index node: key = leaf's first key, value = child oid.
    let index = vec![
        (10u64, 100u64.to_le_bytes().to_vec()),
        (50u64, 200u64.to_le_bytes().to_vec()),
    ];
    let root = BtreeNode::parse(build_node(1, false, true, &index, 8)).unwrap();

    let mut reader = Cursor::new(Vec::new());
    let resolve = |_: &mut Cursor<Vec<u8>>, oid: u64| {
        let block = match oid {
            100 => leaf_left.clone(),
            200 => leaf_right.clone(),
            _ => panic!("unexpected child oid {oid}"),
        };
        BtreeNode::parse(block)
    };

    let value = descend(
        root.clone(),
        &mut reader,
        resolve,
        &30u64.to_le_bytes(),
        cmp_u64,
    )
    .unwrap();
    assert_eq!(value.unwrap(), vec![0xA2; 8]);

    let value = descend(
        root.clone(),
        &mut reader,
        resolve,
        &60u64.to_le_bytes(),
        cmp_u64,
    )
    .unwrap();
    assert_eq!(value.unwrap(), vec![0xB1; 8]);

    let missing = descend(root, &mut reader, resolve, &35u64.to_le_bytes(), cmp_u64).unwrap();
    assert!(missing.is_none());
}

/// Builds a `BtnodeFlags::FIXED_KV_SIZE` node with `toc_off` and
/// `toc_len` set independently of `nkeys` — used to forge the
/// `nkeys`/TOC mismatch that exercises `toc_slice`'s bound check.
fn build_node_with_toc(nkeys: u32, toc_off_in_data: u16, toc_len: u16, root: bool) -> Vec<u8> {
    let mut block = vec![0u8; NODE_SIZE];
    let mut flags = BtnodeFlags::FIXED_KV_SIZE | BtnodeFlags::LEAF;
    if root {
        flags |= BtnodeFlags::ROOT;
    }
    block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
    block[36..40].copy_from_slice(&nkeys.to_le_bytes());
    block[40..42].copy_from_slice(&toc_off_in_data.to_le_bytes());
    block[42..44].copy_from_slice(&toc_len.to_le_bytes());
    block
}

#[test]
fn parse_accepts_a_block_exactly_the_header_size() {
    // A block whose length equals BTN_DATA_OFFSET has just enough room
    // for the header and an empty TOC; it must parse, not be rejected
    // as truncated.
    let block = vec![0u8; BTN_DATA_OFFSET];
    let node = BtreeNode::parse(block).unwrap();
    assert_eq!(node.key_count(), 0);
}

#[test]
fn parse_honours_a_non_zero_table_space_offset() {
    // `btn_table_space.off` is an offset *within* `btn_data`, so
    // `toc_off` must be `BTN_DATA_OFFSET + off`, not `off` alone.
    // Forge a TOC that lives 16 bytes into the data area with a
    // single fixed-kv entry pointing at key 0xAA and value 0xBB.
    let mut block = vec![0u8; NODE_SIZE];
    let flags = BtnodeFlags::FIXED_KV_SIZE | BtnodeFlags::LEAF;
    block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
    block[36..40].copy_from_slice(&1u32.to_le_bytes()); // nkeys
    block[40..42].copy_from_slice(&16u16.to_le_bytes()); // table_space.off = 16
    block[42..44].copy_from_slice(&4u16.to_le_bytes()); // table_space.len = 4

    let toc = BTN_DATA_OFFSET + 16;
    // TOC: k_off = 4 (past the TOC itself), v_off = 8 (from value end).
    block[toc..toc + 2].copy_from_slice(&4u16.to_le_bytes());
    block[toc + 2..toc + 4].copy_from_slice(&8u16.to_le_bytes());
    // Key area starts at toc_off + toc_len = BTN_DATA_OFFSET + 20.
    let key_area = BTN_DATA_OFFSET + 16 + 4;
    block[key_area + 4..key_area + 12].copy_from_slice(&0xAAu64.to_le_bytes());
    let value_end = NODE_SIZE;
    block[value_end - 8..value_end].copy_from_slice(&0xBBu64.to_le_bytes());

    let node = BtreeNode::parse(block).unwrap();
    // If parse had used `BTN_DATA_OFFSET - off` (or anything but `+`)
    // for `toc_off`, the entry's key would read garbage instead of 0xAA.
    let entry = node.entry(0, 8, 8).unwrap();
    assert_eq!(u64::from_le_bytes(entry.key.try_into().unwrap()), 0xAA);
}

#[test]
fn parse_accepts_a_toc_ending_exactly_at_the_block_end() {
    // Off-by-one boundary: `toc_end == block.len()` is in range; only
    // `>` is past the end. Build a non-root node whose TOC fills the
    // remainder of the data area.
    let toc_len_in_bytes = u16::try_from(NODE_SIZE - BTN_DATA_OFFSET).expect("the test fixture value fits in u16");
    let block = build_node_with_toc(0, 0, toc_len_in_bytes, false);
    // Strictly equal to block.len() must succeed; only `toc_end >
    // block.len()` is the error path covered by
    // `rejects_a_toc_past_the_node`.
    BtreeNode::parse(block).unwrap();
}

#[test]
fn level_returns_the_stored_value() {
    // Level is stored verbatim from `btn_level`; assert with a
    // non-{0,1} value so neither `-> 0` nor `-> 1` constant mutations
    // survive.
    let leaf = leaf_entries();
    let mut block = build_node(7, true, true, &leaf, 8);
    // build_node already wrote 7 at offset 34..36; sanity check.
    assert_eq!(
        u16::from_le_bytes(block[34..36].try_into().unwrap()),
        7,
        "test setup"
    );
    let node = BtreeNode::parse(block.clone()).unwrap();
    assert_eq!(node.level(), 7);

    // Also exercise a second non-trivial value to make `-> 7` constant
    // mutations equally unsurvivable.
    block[34..36].copy_from_slice(&42u16.to_le_bytes());
    let other = BtreeNode::parse(block).unwrap();
    assert_eq!(other.level(), 42);
}

#[test]
fn toc_slice_uses_sum_not_product_for_bounds() {
    // Forge `nkeys=2` over a TOC that only holds one entry (4 bytes).
    // The bound `toc_off + toc_len` is `BTN_DATA_OFFSET + 4 = 60`;
    // `toc_off * toc_len` would be `224`, hiding the out-of-range
    // entry. `entry(1, ..)` must surface `Malformed`.
    let block = build_node_with_toc(2, 0, 4, false);
    let node = BtreeNode::parse(block).unwrap();
    let err = node.entry(1, 8, 8).unwrap_err();
    assert!(
        matches!(err, ApfsError::Malformed { reason, .. }
            if reason == "table-of-contents entry out of range"),
        "expected toc-out-of-range malformed, got {err:?}"
    );
}

/// Builds a `kvloc_t` (variable-size) non-leaf node with one entry
/// whose value is `val_len` bytes long. Used to drive a value shorter
/// than the 8-byte child-link minimum into `child_link`.
fn build_kvloc_index_node(key: u64, value: &[u8]) -> Vec<u8> {
    let mut block = vec![0u8; NODE_SIZE];
    // Non-leaf, non-fixed-kv, root.
    let flags = BtnodeFlags::ROOT;
    block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
    block[34..36].copy_from_slice(&1u16.to_le_bytes()); // level = 1
    block[36..40].copy_from_slice(&1u32.to_le_bytes()); // nkeys
    block[40..42].copy_from_slice(&0u16.to_le_bytes()); // table_space.off
    block[42..44].copy_from_slice(&8u16.to_le_bytes()); // table_space.len
    // kvloc_t: u16 k_off, k_len, v_off, v_len.
    let toc = BTN_DATA_OFFSET;
    block[toc..toc + 2].copy_from_slice(&0u16.to_le_bytes()); // k_off
    block[toc + 2..toc + 4].copy_from_slice(&8u16.to_le_bytes()); // k_len
    block[toc + 4..toc + 6].copy_from_slice(&u16::try_from(value.len()).expect("the test fixture value fits in u16").to_le_bytes()); // v_off
    block[toc + 6..toc + 8].copy_from_slice(&u16::try_from(value.len()).expect("the test fixture value fits in u16").to_le_bytes()); // v_len
    // Key bytes.
    let key_area = BTN_DATA_OFFSET + 8;
    block[key_area..key_area + 8].copy_from_slice(&key.to_le_bytes());
    // Value bytes — offset is measured back from the value-area end,
    // which for a root node is `NODE_SIZE - BTREE_INFO_SIZE`.
    let value_end = NODE_SIZE - BTREE_INFO_SIZE;
    let vs = value_end - value.len();
    block[vs..vs + value.len()].copy_from_slice(value);
    // btree_info_t trailer: 8-byte keys, 0 (variable) values.
    let info = NODE_SIZE - BTREE_INFO_SIZE;
    block[info + 4..info + 8].copy_from_slice(&u32::try_from(NODE_SIZE).expect("the test fixture value fits in u32").to_le_bytes());
    block[info + 8..info + 12].copy_from_slice(&8u32.to_le_bytes());
    block[info + 12..info + 16].copy_from_slice(&0u32.to_le_bytes());
    block
}

#[test]
fn child_link_rejects_a_short_value() {
    // A kvloc_t non-leaf with a 4-byte value — shorter than the
    // 8-byte child-link minimum. `descend` must surface `Malformed`;
    // `< 8` mutated to `> 8` would let the short value through.
    let root = BtreeNode::parse(build_kvloc_index_node(10, &[1u8; 4])).unwrap();
    let mut reader = Cursor::new(Vec::new());
    let resolve =
        |_: &mut Cursor<Vec<u8>>, _: u64| -> Result<BtreeNode> { panic!("must not resolve") };
    let err = descend(root, &mut reader, resolve, &10u64.to_le_bytes(), cmp_u64).unwrap_err();
    assert!(
        matches!(err, ApfsError::Malformed { reason, .. }
            if reason == "child link shorter than an object identifier"),
        "expected short-child-link malformed, got {err:?}"
    );
}

#[test]
fn child_index_descends_asymmetric_keys() {
    // Five-key index node: child_index must take multiple binary-
    // search iterations to land on key 30 → child oid 300.
    // The `lo + (hi - lo) / 2` midpoint mutated to `lo + (hi + lo) /
    // 2` returns out-of-range indices on the second iteration, so
    // the descent surfaces `Malformed` instead of the right child.
    let index = vec![
        (10u64, 100u64.to_le_bytes().to_vec()),
        (20u64, 200u64.to_le_bytes().to_vec()),
        (30u64, 300u64.to_le_bytes().to_vec()),
        (40u64, 400u64.to_le_bytes().to_vec()),
        (50u64, 500u64.to_le_bytes().to_vec()),
    ];
    let root_block = build_node(1, false, true, &index, 8);
    let root = BtreeNode::parse(root_block).unwrap();

    // Synthesise five distinct one-entry leaves keyed at each index.
    let leaves: Vec<Vec<u8>> = [10u64, 20, 30, 40, 50]
        .into_iter()
        .map(|k| build_node(0, true, false, &[(k, vec![u8::try_from(k).expect("the test fixture value fits in u8"); 8])], 8))
        .collect();

    let mut reader = Cursor::new(Vec::new());
    let resolve = |_: &mut Cursor<Vec<u8>>, oid: u64| {
        let i = match oid {
            100 => 0,
            200 => 1,
            300 => 2,
            400 => 3,
            500 => 4,
            _ => panic!("unexpected child oid {oid}"),
        };
        BtreeNode::parse(leaves[i].clone())
    };

    for (search, expected) in [(10u64, 10u8), (20, 20), (30, 30), (40, 40), (50, 50)] {
        let value = descend(
            root.clone(),
            &mut reader,
            resolve,
            &search.to_le_bytes(),
            cmp_u64,
        )
        .unwrap()
        .unwrap_or_else(|| panic!("missing value for {search}"));
        assert_eq!(value, vec![expected; 8]);
    }
}
