use super::*;

fn root_item(key_offset: u64, generation: u64) -> RootItem {
    RootItem {
        key_offset,
        generation,
        logical: 4096,
        flags: 0,
        level: 0,
    }
}

#[test]
fn newest_root_is_selected_by_transaction_key_offset() {
    let older_key_with_newer_block = root_item(10, 100);
    let newer_key_with_older_block = root_item(11, 99);

    assert!(should_replace_root(None, &older_key_with_newer_block));
    assert!(should_replace_root(
        Some(&older_key_with_newer_block),
        &newer_key_with_older_block
    ));
    assert!(!should_replace_root(
        Some(&newer_key_with_older_block),
        &older_key_with_newer_block
    ));
}

#[test]
fn root_block_owner_must_match_the_requested_subvolume() {
    let expected_tree = FIRST_FREE_OBJECT_ID;
    let foreign_tree = FIRST_FREE_OBJECT_ID + 1;

    assert!(
        validate_tree_identity(expected_tree, Some(7), None, foreign_tree, 7, None, 4096,).is_err()
    );
}

#[test]
fn child_block_owner_may_name_another_subvolume_tree() {
    let expected_tree = FIRST_FREE_OBJECT_ID;
    let relocated_from = FIRST_FREE_OBJECT_ID + 1;
    let first_key = DiskKey::range_start(FIRST_FREE_OBJECT_ID, INODE_ITEM_KEY);

    validate_tree_identity(
        expected_tree,
        Some(7),
        Some(first_key),
        relocated_from,
        7,
        Some(first_key),
        4096,
    )
    .expect("relocated subvolume child owner");
}
