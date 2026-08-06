#[test]
fn descriptor_rejects_bad_data_checksum_v3() {
    let bs = 4096usize;
    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&42u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    // Tag's per-block checksum field: plant a wrong value so the per-tag
    // check fires once the descriptor tail checksum has been satisfied.
    desc[24..28].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

    // Compute a valid descriptor tail checksum so we reach the per-tag
    // check rather than stopping on DescriptorTailChecksumInvalid first.
    let seed = WalkState::new(&dummy_source(u32::try_from(bs).expect("the test fixture value fits in u32"), JournalChecksumMode::V3Crc32c)).seed;
    let tail_off = bs - 4;
    let tail_csum =
        crate::journal::checksum::block_tail_checksum_split(seed, &desc[..tail_off], &[]);
    desc[tail_off..tail_off + 4].copy_from_slice(&tail_csum.to_be_bytes());

    let mut data = alloc::vec![0u8; bs];
    data[0..8].copy_from_slice(b"WRONGCSM");

    let mut mem = InMemJournal {
        blocks: alloc::vec![alloc::vec![0u8; bs], desc, data, alloc::vec![0u8; bs]],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };
    let mut st = WalkState::new(&dummy_source(u32::try_from(bs).expect("the test fixture value fits in u32"), JournalChecksumMode::V3Crc32c));
    mem.read_block(1, &mut st.scratch).expect("read descriptor");
    let reason = process_descriptor(&mut mem, &mut st).expect("process");
    assert!(matches!(
        reason,
        Some(StopReason::DataBlockChecksumInvalid { fs_block: 42 })
    ));
}

// ---- issue #118: external journal device replay ----

const EXT_JOURNAL_BLOCKS: u32 = 8;
const EXT_JOURNAL_SEQ: u32 = 100;

/// Build an `mke2fs -O journal_dev`-shaped external-journal device
/// image. Device block 0 is the journal device's own ext4
/// superblock region (unread by the parser, left as padding here);
/// the jbd2 area begins at device block `base` — block `base` is the
/// jbd2 superblock, and jbd2 block `N` is at device block `base + N`.
/// jbd2 blocks 1..3 hold one classic transaction (descriptor, data,
/// commit) targeting filesystem block `target_fs_block`, whose
/// content is `data_fill`. `feature_incompat` is left zero so the
/// un-checksummed blocks validate.
fn build_external_journal(
    block_size: u32,
    uuid: [u8; 16],
    target_fs_block: u32,
    data_fill: u8,
) -> Vec<u8> {
    let bs = block_size as usize;
    let base = usize::try_from(crate::journal::source::external_journal_base_block(block_size)).expect("the test fixture value fits in usize");
    // Device blocks: [0..base) ext4-device-sb region, then the
    // `EXT_JOURNAL_BLOCKS`-block jbd2 journal area.
    let mut buf = alloc::vec![0u8; bs * (base + EXT_JOURNAL_BLOCKS as usize)];

    // --- jbd2 block 0 (device block `base`): superblock v2 (BE) ---
    let sb = &mut buf[base * bs..(base + 1) * bs];
    sb[0x00..0x04].copy_from_slice(&JBD_MAGIC.to_be_bytes());
    sb[0x04..0x08].copy_from_slice(&4u32.to_be_bytes()); // h_blocktype: superblock v2
    sb[0x0C..0x10].copy_from_slice(&block_size.to_be_bytes()); // s_blocksize
    sb[0x10..0x14].copy_from_slice(&EXT_JOURNAL_BLOCKS.to_be_bytes()); // s_maxlen
    sb[0x14..0x18].copy_from_slice(&1u32.to_be_bytes()); // s_first
    sb[0x18..0x1C].copy_from_slice(&EXT_JOURNAL_SEQ.to_be_bytes()); // s_sequence
    sb[0x1C..0x20].copy_from_slice(&1u32.to_be_bytes()); // s_start
    // 0x28 feature_incompat stays 0 → no journal checksums.
    sb[0x30..0x40].copy_from_slice(&uuid); // s_uuid
    sb[0x40..0x44].copy_from_slice(&1u32.to_be_bytes()); // s_nr_users

    // jbd2 block N → device block `base + N`.
    let jbd_block = |n: usize| (base + n) * bs;

    // --- jbd2 block 1: descriptor with one classic tag ---
    let desc_off = jbd_block(1);
    let desc = &mut buf[desc_off..desc_off + bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, EXT_JOURNAL_SEQ));
    desc[12..16].copy_from_slice(&target_fs_block.to_be_bytes()); // tag blocknr
    desc[16..18].copy_from_slice(&0u16.to_be_bytes()); // tag checksum
    desc[18..20].copy_from_slice(
        &(u16::try_from(crate::journal::tags::TAG_FLAG_LAST | crate::journal::tags::TAG_FLAG_SAME_UUID
           ).expect("the test fixture value fits in u16"))
            .to_be_bytes(),
    );

    // --- jbd2 block 2: the data block (first 4 bytes ≠ JBD_MAGIC) ---
    buf[jbd_block(2)..jbd_block(2) + bs].fill(data_fill);

    // --- jbd2 block 3: commit ---
    buf[jbd_block(3)..jbd_block(3) + 12].copy_from_slice(&hdr(BT_COMMIT, EXT_JOURNAL_SEQ));

    buf
}

#[test]
fn external_journal_uuid_mismatch_is_rejected() {
    // ext4.img is an internal-journal filesystem → s_journal_uuid is
    // all-zero. An external journal advertising a different UUID must
    // be rejected.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(path).expect("read ext4 fixture");
    let mut fs = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");

    let wrong_uuid = [0xAA; 16];
    let journal_buf = build_external_journal(ext.block_size(), wrong_uuid, 500, 0xCD);
    let mut journal = std::io::Cursor::new(journal_buf);

    let err = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
        .expect_err("UUID mismatch must be rejected");
    match err {
        crate::error::ExtError::JournalUuidMismatch {
            fs_uuid,
            journal_uuid,
        } => {
            assert_eq!(fs_uuid, [0u8; 16]);
            assert_eq!(journal_uuid, wrong_uuid);
        }
        other => panic!("expected JournalUuidMismatch, got {other:?}"),
    }
}

#[test]
fn external_journal_replays_classic_transaction() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(path).expect("read ext4 fixture");
    let mut fs = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");
    // ext4.img has an internal journal, so s_journal_uuid is zero;
    // the synthetic external journal carries the same zero UUID.
    let target = 500u32;
    let journal_buf =
        build_external_journal(ext.block_size(), ext.journal_uuid(), target, 0xCD);
    let mut journal = std::io::Cursor::new(journal_buf);

    let jr = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
        .expect("external journal replay");

    // The classic transaction from the *external* device was walked
    // and committed; its single data block was applied.
    assert_eq!(jr.plan().committed.len(), 1, "one committed transaction");
    assert_eq!(jr.plan().committed[0].data_blocks_applied, 1);

    // The overlay now serves the journal-recorded content for the
    // target filesystem block.
    let mut overlay_reader = crate::OverlayReader::new(&mut fs, &jr);
    overlay_reader
        .seek(SeekFrom::Start(
            u64::from(target) * u64::from(ext.block_size()),
        ))
        .expect("seek overlay");
    let mut block = alloc::vec![0u8; ext.block_size() as usize];
    overlay_reader
        .read_exact(&mut block)
        .expect("read overlay block");
    assert!(
        block.iter().all(|&b| b == 0xCD),
        "external-journal data block must be applied to the overlay",
    );
}

#[test]
fn open_with_external_journal_gates_journal_dev_flag() {
    // Patch ext4.img to advertise INCOMPAT_JOURNAL_DEV (bit 0x0008
    // at superblock offset 0x60). The single-reader open paths must
    // reject it; open_with_external_journal must accept it.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let mut bytes = std::fs::read(path).expect("read ext4 fixture");
    let incompat_off = 1024 + 0x60;
    let mut incompat = u32::from_le_bytes(
        bytes[incompat_off..incompat_off + 4]
            .try_into()
            .expect("fixed slice"),
    );
    incompat |= 0x0000_0008; // INCOMPAT_JOURNAL_DEV
    bytes[incompat_off..incompat_off + 4].copy_from_slice(&incompat.to_le_bytes());

    // Single-reader paths reject.
    let mut fs = std::io::Cursor::new(bytes.clone());
    assert!(matches!(
        crate::Ext::open_lenient(&mut fs),
        Err(crate::error::ExtError::UnsupportedJournalDevice),
    ));
    let mut fs = std::io::Cursor::new(bytes.clone());
    assert!(matches!(
        crate::Ext::new(&mut fs),
        Err(crate::error::ExtError::UnsupportedJournalDevice),
    ));

    // The dual-reader path parses the filesystem and validates the
    // external journal (zero UUID matches the untouched s_journal_uuid).
    let block_size = 4096u32;
    let journal_buf = build_external_journal(block_size, [0u8; 16], 500, 0xCD);
    let mut fs = std::io::Cursor::new(bytes);
    let mut journal = std::io::Cursor::new(journal_buf);
    let ext = crate::Ext::open_with_external_journal(&mut fs, &mut journal)
        .expect("open_with_external_journal must accept INCOMPAT_JOURNAL_DEV");
    assert!(ext.uses_external_journal());
}

#[test]
fn external_journal_with_fast_commit_is_rejected() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(path).expect("read ext4 fixture");
    let mut fs = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");

    let mut journal_buf =
        build_external_journal(ext.block_size(), ext.journal_uuid(), 500, 0xCD);
    // Set JBD2_FEATURE_INCOMPAT_FAST_COMMIT (0x0020) in the jbd2 sb,
    // which lives at device block `base`, not byte 0.
    let bs = ext.block_size() as usize;
    let sb_off =
        usize::try_from(crate::journal::source::external_journal_base_block(ext.block_size())).expect("the test fixture value fits in usize") * bs;
    let fc_bit = 0x0000_0020u32;
    journal_buf[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&fc_bit.to_be_bytes());
    let mut journal = std::io::Cursor::new(journal_buf);

    let err = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
        .expect_err("external journal + fast-commit must be rejected");
    assert!(matches!(
        err,
        crate::error::ExtError::ExternalJournalFastCommitUnsupported
    ));
}
