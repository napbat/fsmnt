use super::*;

#[test]
fn build_decryptor_aes128_xts() {
    let fvek = vec![0x42u8; 32];
    let dec = build_decryptor(EncryptionMethod::Aes128Xts, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_aes256_xts() {
    let fvek = vec![0x42u8; 64];
    let dec = build_decryptor(EncryptionMethod::Aes256Xts, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_aes128_cbc() {
    let fvek = vec![0x42u8; 16];
    let dec = build_decryptor(EncryptionMethod::Aes128Cbc, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_aes256_cbc() {
    let fvek = vec![0x42u8; 32];
    let dec = build_decryptor(EncryptionMethod::Aes256Cbc, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_diffuser_128() {
    let fvek = vec![0x42u8; 64];
    let dec = build_decryptor(EncryptionMethod::Aes128CbcDiffuser, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_diffuser_256() {
    let fvek = vec![0x42u8; 64];
    let dec = build_decryptor(EncryptionMethod::Aes256CbcDiffuser, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn build_decryptor_fvek_too_short() {
    let fvek = vec![0x42u8; 8];
    let err = build_decryptor(EncryptionMethod::Aes256Xts, &fvek).unwrap_err();
    assert!(matches!(err, BitLockerError::SectorLayoutError { .. }));
}

#[test]
fn build_decryptor_with_algo_prefix() {
    let mut fvek = Vec::with_capacity(34);
    fvek.extend_from_slice(&0x8004u16.to_le_bytes());
    fvek.extend_from_slice(&[0x42u8; 32]);
    let dec = build_decryptor(EncryptionMethod::Aes128Xts, &fvek);
    assert!(dec.is_ok());
}

#[test]
fn fvek_algo_prefix_known_ids() {
    use zerocopy::IntoBytes;
    let make = |id: u16| {
        let bytes = id.to_le_bytes();
        FvekAlgoPrefix::read_from_bytes(bytes.as_bytes())
            .unwrap()
            .is_known()
    };
    assert!(make(0x8000));
    assert!(make(0x8005));
    assert!(!make(0x1234));
}

fn make_test_volume(
    plaintext_sectors: &[&[u8; 512]],
) -> UnlockedVolume<std::io::Cursor<Vec<u8>>> {
    use aes::cipher::KeyInit;
    let key = [0x42u8; 32];

    let mut disk = Vec::new();
    for (i, sector) in plaintext_sectors.iter().enumerate() {
        let tweak = AesXtsDecryptor::sector_tweak(
            u64::try_from(i).expect("the test sector index fits in u64"),
        );
        let cipher1 = aes::Aes128::new(key[..16].into());
        let cipher2 = aes::Aes128::new(key[16..32].into());
        let xts = xts_mode::Xts128::<aes::Aes128>::new(cipher1, cipher2);
        let mut encrypted = **sector;
        xts.encrypt_sector(&mut encrypted, tweak);
        disk.extend_from_slice(&encrypted);
    }

    let total_sectors =
        u64::try_from(plaintext_sectors.len()).expect("the test sector count fits in u64");
    let metadata = BitLockerMetadata::new_for_test(
        EncryptionMethod::Aes128Xts,
        u64::try_from(disk.len()).expect("the test disk length fits in u64"),
        512,
        total_sectors,
    );

    UnlockedVolume {
        reader: std::io::Cursor::new(disk),
        metadata,
        decryptor: Decryptor::Xts(AesXtsDecryptor::new(key.to_vec()).unwrap()),
        sector_size: 512,
        position: 0,
        buf: Zeroizing::new(Vec::new()),
        buf_start_sector: None,
        buf_valid_sectors: 0,
        chunk_sectors: MIN_CHUNK_SECTORS,
    }
}

#[test]
fn read_full_sector() {
    let sector0 = &[0xABu8; 512];
    let mut vol = make_test_volume(&[sector0]);
    let mut buf = [0u8; 512];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert_eq!(buf, *sector0);
}

#[test]
fn read_partial_sector() {
    let sector0 = &[0xCDu8; 512];
    let mut vol = make_test_volume(&[sector0]);
    let mut buf = [0u8; 16];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 16);
    assert_eq!(buf, [0xCD; 16]);
}

#[test]
fn decryption_buffer_grows_only_to_the_initial_read_ahead() {
    let sector = &[0x5au8; 512];
    let mut volume = make_test_volume(&[sector; MIN_CHUNK_SECTORS + 1]);
    assert!(volume.buf.is_empty());

    let mut output = [0_u8; 1];
    volume.read_exact(&mut output).unwrap();
    assert_eq!(output, [0x5a]);
    assert_eq!(volume.buf.len(), MIN_CHUNK_SECTORS * 512);
    assert!(volume.buf.len() < MAX_CHUNK_SECTORS * 512);
}

#[test]
fn read_across_sector_boundary() {
    let sector0 = &[0xAAu8; 512];
    let sector1 = &[0xBBu8; 512];
    let mut vol = make_test_volume(&[sector0, sector1]);

    // Seek to 256 bytes before sector boundary
    vol.seek(SeekFrom::Start(256)).unwrap();
    let mut buf = [0u8; 512];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert_eq!(&buf[..256], &[0xAA; 256]);
    assert_eq!(&buf[256..], &[0xBB; 256]);
}

#[test]
fn seek_and_read() {
    let sector0 = &[0x11u8; 512];
    let sector1 = &[0x22u8; 512];
    let mut vol = make_test_volume(&[sector0, sector1]);

    vol.seek(SeekFrom::Start(512)).unwrap();
    let mut buf = [0u8; 512];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert_eq!(buf, [0x22; 512]);
}

#[test]
fn read_at_eof_returns_zero() {
    let sector0 = &[0xEEu8; 512];
    let mut vol = make_test_volume(&[sector0]);
    vol.seek(SeekFrom::Start(512)).unwrap();
    let mut buf = [0u8; 16];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn seek_from_end() {
    let sector0 = &[0xFFu8; 512];
    let mut vol = make_test_volume(&[sector0]);
    let pos = vol.seek(SeekFrom::End(-16)).unwrap();
    assert_eq!(pos, 496);
    let mut buf = [0u8; 16];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 16);
    assert_eq!(buf, [0xFF; 16]);
}

#[test]
fn seek_beyond_u64_max_errors() {
    let sector0 = &[0u8; 512];
    let mut vol = make_test_volume(&[sector0]);
    // Seek to end, then try to go past u64::MAX
    vol.seek(SeekFrom::Start(u64::MAX)).unwrap();
    let err = vol.seek(SeekFrom::Current(1));
    assert!(err.is_err());
}

#[test]
fn seek_negative_errors() {
    let sector0 = &[0u8; 512];
    let mut vol = make_test_volume(&[sector0]);
    let err = vol.seek(SeekFrom::Start(0));
    assert!(err.is_ok());
    let err = vol.seek(SeekFrom::Current(-1));
    assert!(err.is_err());
}

/// Build a volume where only the first `encrypted_sectors` sectors are
/// encrypted; remaining sectors are stored as raw plaintext on disk.
fn make_partial_volume(
    plaintext_sectors: &[&[u8; 512]],
    encrypted_sectors: usize,
) -> UnlockedVolume<std::io::Cursor<Vec<u8>>> {
    use aes::cipher::KeyInit;
    let key = [0x42u8; 32];

    let mut disk = Vec::new();
    for (i, sector) in plaintext_sectors.iter().enumerate() {
        if i < encrypted_sectors {
            let tweak = AesXtsDecryptor::sector_tweak(
                u64::try_from(i).expect("the test sector index fits in u64"),
            );
            let cipher1 = aes::Aes128::new(key[..16].into());
            let cipher2 = aes::Aes128::new(key[16..32].into());
            let xts = xts_mode::Xts128::<aes::Aes128>::new(cipher1, cipher2);
            let mut encrypted = **sector;
            xts.encrypt_sector(&mut encrypted, tweak);
            disk.extend_from_slice(&encrypted);
        } else {
            // Stored as plaintext (not encrypted on disk)
            disk.extend_from_slice(*sector);
        }
    }

    let total_sectors =
        u64::try_from(plaintext_sectors.len()).expect("the test sector count fits in u64");
    let encrypted_volume_size =
        u64::try_from(encrypted_sectors).expect("the encrypted test sector count fits in u64")
            * 512;
    let metadata = BitLockerMetadata::new_for_test(
        EncryptionMethod::Aes128Xts,
        encrypted_volume_size,
        512,
        total_sectors,
    );

    UnlockedVolume {
        reader: std::io::Cursor::new(disk),
        metadata,
        decryptor: Decryptor::Xts(AesXtsDecryptor::new(key.to_vec()).unwrap()),
        sector_size: 512,
        position: 0,
        buf: Zeroizing::new(Vec::new()),
        buf_start_sector: None,
        buf_valid_sectors: 0,
        chunk_sectors: MIN_CHUNK_SECTORS,
    }
}

#[test]
fn read_outside_encrypted_region_passes_through() {
    // 4 sectors total, only first 2 encrypted
    let s0 = &[0xAAu8; 512];
    let s1 = &[0xBBu8; 512];
    let s2 = &[0xCCu8; 512]; // plaintext on disk
    let s3 = &[0xDDu8; 512]; // plaintext on disk
    let mut vol = make_partial_volume(&[s0, s1, s2, s3], 2);

    // Read sector 2 — should be raw plaintext passthrough
    vol.seek(SeekFrom::Start(1024)).unwrap();
    let mut buf = [0u8; 512];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert_eq!(buf, [0xCC; 512]);

    // Read sector 3
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert_eq!(buf, [0xDD; 512]);
}

#[test]
fn read_spanning_encrypted_boundary() {
    // 4 sectors, first 2 encrypted
    let s0 = &[0x11u8; 512];
    let s1 = &[0x22u8; 512];
    let s2 = &[0x33u8; 512]; // plaintext
    let s3 = &[0x44u8; 512]; // plaintext
    let mut vol = make_partial_volume(&[s0, s1, s2, s3], 2);

    // Seek to 256 bytes before the encrypted/unencrypted boundary
    vol.seek(SeekFrom::Start(512 + 256)).unwrap();
    let mut buf = [0u8; 512];
    let n = vol.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    // First 256 bytes from sector 1 (encrypted, decrypted to 0x22)
    assert_eq!(&buf[..256], &[0x22; 256]);
    // Last 256 bytes from sector 2 (plaintext passthrough, 0x33)
    assert_eq!(&buf[256..], &[0x33; 256]);
}

#[test]
fn encrypted_and_unencrypted_sectors_both_correct() {
    // Verify encrypted sectors decrypt properly alongside plaintext ones
    let s0 = &[0xAAu8; 512];
    let s1 = &[0xBBu8; 512]; // plaintext on disk
    let mut vol = make_partial_volume(&[s0, s1], 1);

    // Read sector 0 (encrypted) — should decrypt
    let mut buf = [0u8; 512];
    vol.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xAA; 512]);

    // Read sector 1 (plaintext) — should passthrough
    vol.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xBB; 512]);
}

#[test]
fn cache_hit_reuses_sector() {
    let sector0 = &[0xAAu8; 512];
    let mut vol = make_test_volume(&[sector0]);

    // First read populates cache
    let mut buf1 = [0u8; 16];
    vol.read_exact(&mut buf1).unwrap();

    // Seek back and read again — should hit cache
    vol.seek(SeekFrom::Start(0)).unwrap();
    let mut buf2 = [0u8; 16];
    vol.read_exact(&mut buf2).unwrap();

    assert_eq!(buf1, buf2);
}
